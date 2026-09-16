rule DCRat_salt
{
    meta:
        description = "Detects DCRat by hardcoded salt in Aes256 class."
        reference = "Aes256.cs"
        
    strings:
        $salt = "DcRatByqwqdanchun" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and $salt
}