rule pdf_comment_present_stringless
{
    meta:
        author = "kyle eaton"
        date = "02/12/2024"
        day = "3/100"
    condition:
            uint32be(0) == 0x25504446 and 
        uint32be(1) == 0x5044462d and 
        uint8(8) == 0x0d
}