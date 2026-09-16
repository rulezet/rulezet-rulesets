rule Arcane_cystack_8c7dcc2b
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_8c7dcc2b"

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
        $key_17 = "ISO Key:" ascii
        $key_18 = "Internal IP:" ascii
        $key_19 = "MACAddress:" ascii
        $key_20 = "Manufacturer:" ascii
        $key_21 = "MaxClockSpeed:" ascii
        $key_22 = "Model:" ascii
        $key_23 = "Name:" ascii
        $key_24 = "NumberOfCores:" ascii
        $key_25 = "OSArchitecture:" ascii
        $key_26 = "Product:" ascii
        $key_27 = "Quarto individual 1:" ascii
        $key_28 = "Quarto individual 2:" ascii
        $key_29 = "Quarto individual 3:" ascii
        $key_30 = "ReleaseDate:" ascii
        $key_31 = "SMBIOSBIOSVersion:" ascii
        $key_32 = "SerialNumber:" ascii
        $key_33 = "Size:" ascii
        $key_34 = "Speed:" ascii
        $key_35 = "Version:" ascii
        $key_36 = "Worker:" ascii

    condition:
        all of ($key_*)
}