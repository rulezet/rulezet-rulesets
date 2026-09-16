rule Arcane_cystack_ddbcb63f
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_ddbcb63f"

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
        $key_31 = "Worker:" ascii

    condition:
        all of ($key_*)
}