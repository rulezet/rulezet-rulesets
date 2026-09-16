rule Arcane_cystack_d061dd05
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_d061dd05"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Clipboard:" ascii
        $key_5 = "Date Install:" ascii
        $key_6 = "Default:" ascii
        $key_7 = "Description:" ascii
        $key_8 = "DeviceID:" ascii
        $key_9 = "External IP:" ascii
        $key_10 = "FileSystem:" ascii
        $key_11 = "FreeSpace:" ascii
        $key_12 = "FullName:" ascii
        $key_13 = "Gateway IP:" ascii
        $key_14 = "IPEnabled:" ascii
        $key_15 = "ISO Key:" ascii
        $key_16 = "Internal IP:" ascii
        $key_17 = "MACAddress:" ascii
        $key_18 = "Manufacturer:" ascii
        $key_19 = "MaxClockSpeed:" ascii
        $key_20 = "Model:" ascii
        $key_21 = "Name:" ascii
        $key_22 = "NumberOfCores:" ascii
        $key_23 = "OSArchitecture:" ascii
        $key_24 = "Product:" ascii
        $key_25 = "ReleaseDate:" ascii
        $key_26 = "SMBIOSBIOSVersion:" ascii
        $key_27 = "SerialNumber:" ascii
        $key_28 = "Size:" ascii
        $key_29 = "Speed:" ascii
        $key_30 = "Version:" ascii

    condition:
        all of ($key_*)
}