rule CSDataCollectedStealer_data_collected_successfully_ack
{
    meta:
        family = "CSDataCollectedStealer"
        fingerprint_id = "data_collected_successfully_ack"

    strings:
        $key_0 = "Computer:" ascii
        $key_1 = "IP:" ascii

    condition:
        all of ($key_*)
}