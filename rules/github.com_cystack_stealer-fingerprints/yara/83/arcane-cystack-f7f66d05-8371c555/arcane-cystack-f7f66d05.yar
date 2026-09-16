rule Arcane_cystack_f7f66d05
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_f7f66d05"

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
        $key_12 = "From:" ascii
        $key_13 = "FullName:" ascii
        $key_14 = "Gateway IP:" ascii
        $key_15 = "IPEnabled:" ascii
        $key_16 = "ISO Key:" ascii
        $key_17 = "Internal IP:" ascii
        $key_18 = "MACAddress:" ascii
        $key_19 = "Manufacturer:" ascii
        $key_20 = "MaxClockSpeed:" ascii
        $key_21 = "Model:" ascii
        $key_22 = "Name:" ascii
        $key_23 = "NumberOfCores:" ascii
        $key_24 = "OSArchitecture:" ascii
        $key_25 = "Product:" ascii
        $key_26 = "ReleaseDate:" ascii
        $key_27 = "SMBIOSBIOSVersion:" ascii
        $key_28 = "SerialNumber:" ascii
        $key_29 = "Size:" ascii
        $key_30 = "Speed:" ascii
        $key_31 = "Version:" ascii
        $key_32 = "Vhicile no:" ascii

    condition:
        all of ($key_*)
}