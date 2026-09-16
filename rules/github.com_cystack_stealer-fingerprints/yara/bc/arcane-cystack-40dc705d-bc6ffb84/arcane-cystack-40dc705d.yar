rule Arcane_cystack_40dc705d
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_40dc705d"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "Capacity:" ascii
        $key_2 = "Caption:" ascii
        $key_3 = "ChassisTypes:" ascii
        $key_4 = "Default:" ascii
        $key_5 = "Description:" ascii
        $key_6 = "DeviceID:" ascii
        $key_7 = "External IP:" ascii
        $key_8 = "FileSystem:" ascii
        $key_9 = "FreeSpace:" ascii
        $key_10 = "FullName:" ascii
        $key_11 = "Gateway IP:" ascii
        $key_12 = "IPEnabled:" ascii
        $key_13 = "ISO Key:" ascii
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