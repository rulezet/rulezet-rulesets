rule Arcane_cystack_bcbae85e
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_bcbae85e"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Date Install:" ascii
        $key_5 = "Default:" ascii
        $key_6 = "Description:" ascii
        $key_7 = "DeviceID:" ascii
        $key_8 = "FileSystem:" ascii
        $key_9 = "FreeSpace:" ascii
        $key_10 = "FullName:" ascii
        $key_11 = "Gateway IP:" ascii
        $key_12 = "IPEnabled:" ascii
        $key_13 = "Internal IP:" ascii
        $key_14 = "MACAddress:" ascii
        $key_15 = "Manufacturer:" ascii
        $key_16 = "MaxClockSpeed:" ascii
        $key_17 = "Model:" ascii
        $key_18 = "Name:" ascii
        $key_19 = "NumberOfCores:" ascii
        $key_20 = "OSArchitecture:" ascii
        $key_21 = "Product:" ascii
        $key_22 = "ReleaseDate:" ascii
        $key_23 = "SMBIOSBIOSVersion:" ascii
        $key_24 = "SerialNumber:" ascii
        $key_25 = "Size:" ascii
        $key_26 = "Speed:" ascii
        $key_27 = "Version:" ascii
        $key_28 = "Worker:" ascii

    condition:
        all of ($key_*)
}