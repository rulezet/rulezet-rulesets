rule CryptBot_cystack_711e1005
{
    meta:
        family = "CryptBot"
        fingerprint_id = "cystack_711e1005"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "Display Resolution:" ascii
        $key_2 = "GPU:" ascii
        $key_3 = "Installed software:" ascii
        $key_4 = "Keyboard Languages:" ascii
        $key_5 = "OS:" ascii
        $key_6 = "RAM:" ascii

    condition:
        all of ($key_*)
}