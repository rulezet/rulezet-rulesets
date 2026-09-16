rule Arcane_cystack_6d23dc0d
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_6d23dc0d"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Clipboard:" ascii
        $key_5 = "Data Check-in:" ascii
        $key_6 = "Data Check-out:" ascii
        $key_7 = "Date Install:" ascii
        $key_8 = "Default:" ascii
        $key_9 = "Description:" ascii
        $key_10 = "DeviceID:" ascii
        $key_11 = "External IP:" ascii
        $key_12 = "FileSystem:" ascii
        $key_13 = "FreeSpace:" ascii
        $key_14 = "FullName:" ascii
        $key_15 = "Gateway IP:" ascii
        $key_16 = "IPEnabled:" ascii
        $key_17 = "Internal IP:" ascii
        $key_18 = "MACAddress:" ascii
        $key_19 = "Manufacturer:" ascii
        $key_20 = "MaxClockSpeed:" ascii
        $key_21 = "Model:" ascii
        $key_22 = "Name:" ascii
        $key_23 = "NumberOfCores:" ascii
        $key_24 = "OSArchitecture:" ascii
        $key_25 = "Product:" ascii
        $key_26 = "Quarto individual 1:" ascii
        $key_27 = "Quarto individual 2:" ascii
        $key_28 = "Quarto individual 3:" ascii
        $key_29 = "ReleaseDate:" ascii
        $key_30 = "SMBIOSBIOSVersion:" ascii
        $key_31 = "SerialNumber:" ascii
        $key_32 = "Size:" ascii
        $key_33 = "Speed:" ascii
        $key_34 = "Version:" ascii
        $key_35 = "Worker:" ascii

    condition:
        all of ($key_*)
}