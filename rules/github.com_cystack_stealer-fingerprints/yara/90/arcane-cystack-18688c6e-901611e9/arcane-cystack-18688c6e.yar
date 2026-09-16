rule Arcane_cystack_18688c6e
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_18688c6e"

    strings:
        $key_0 = "AdapterRAM:" ascii
        $key_1 = "BatteryStatus:" ascii
        $key_2 = "Capacity:" ascii
        $key_3 = "Caption:" ascii
        $key_4 = "ChassisTypes:" ascii
        $key_5 = "Clipboard:" ascii
        $key_6 = "Date Install:" ascii
        $key_7 = "Description:" ascii
        $key_8 = "DeviceID:" ascii
        $key_9 = "EstimatedChargeRemaining:" ascii
        $key_10 = "External IP:" ascii
        $key_11 = "FileSystem:" ascii
        $key_12 = "FreeSpace:" ascii
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
        $key_32 = "Worker:" ascii

    condition:
        all of ($key_*)
}