rule _fat
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

                 
    strings:
        $fat = { CA FE BA BE }
 
    condition:
        $fat at 0 and uint32(4) < 0x14000000
}