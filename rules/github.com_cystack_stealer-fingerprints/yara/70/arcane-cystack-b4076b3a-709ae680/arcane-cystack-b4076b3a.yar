rule Arcane_cystack_b4076b3a
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_b4076b3a"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Clipboard:" ascii
        $key_5 = "Date Install:" ascii
        $key_6 = "Description:" ascii
        $key_7 = "DeviceID:" ascii
        $key_8 = "External IP:" ascii
        $key_9 = "FileSystem:" ascii
        $key_10 = "FreeSpace:" ascii
        $key_11 = "FullName:" ascii
        $key_12 = "Gateway IP:" ascii
        $key_13 = "IPEnabled:" ascii
        $key_14 = "Internal IP:" ascii
        $key_15 = "MACAddress:" ascii
        $key_16 = "Manufacturer:" ascii
        $key_17 = "MaxClockSpeed:" ascii
        $key_18 = "Model:" ascii
        $key_19 = "Name:" ascii
        $key_20 = "NumberOfCores:" ascii
        $key_21 = "OSArchitecture:" ascii
        $key_22 = "Product:" ascii
        $key_23 = "ReleaseDate:" ascii
        $key_24 = "SMBIOSBIOSVersion:" ascii
        $key_25 = "SerialNumber:" ascii
        $key_26 = "Size:" ascii
        $key_27 = "Speed:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "Worker:" ascii

    condition:
        all of ($key_*)
}