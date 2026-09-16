rule infected_188_120_231_151_2018_01_07a_shells_fack {
  meta:
    description = "shells - file fack.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "a2281fdbfeb4e0bef66c0d174fff9719253ff712c1b3d8cc554a5e6ac3caee89"

  strings:
    $s1  = "$fack = 'CgoKZXJyb3JfcmVwb3J0aW5nKDApOwovL2Vycm9yX3JlcG9ydGluZyhFX0FMTCk7CnNldF90aW1lX2xpbWl0KDApOwoKCgpjbGFzcyBJbmplY3RvckNvbXB" ascii
    $s2  = "oc2VsZWN0KzErZnJvbShzZWxlY3QrY291bnQoKiksY29uY2F0KChzZWxlY3QrKHNlbGVjdCsoU0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCgweDdlLDB4MjcsJTI3b2xvbG8" ascii  
    $s3  = "0K2NvbmNhdCgweDdlLDB4MjcsJTI3b2xvbG8lMjcsMHgyNywweDdlKStGUk9NK2luZm9ybWF0aW9uX3NjaGVtYS5zY2hlbWF0YStMSU1JVCsxKSkrZnJvbStpbmZvcm1" ascii  
    $s4  = "zNTM2LDB4MzEzMDMyMzUzNDM4MzAzMDM1MzYsMHgzMTMwMzIzNTM0MzgzMDMwMzUzNiwoc2VsZWN0IGRpc3RpbmN0IGNvbmNhdCgweDdlLDB4MjcsdW5oZXgoSGV4KGN" ascii  
    $s5  = "IRUNLIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKENBU1QoSUQgQVMgQ0hBUiksJyAnKSwnanphcnF0JyxJRk5VTEwoQ0FTVChJU19QRVJJT0QgQVMgQ0hBUik" ascii  
    $s6  = "faWQ9MiBVTklPTiBBTEwgU0VMRUNUIChTRUxFQ1QgQ09OQ0FUKCdxdmtxcScsSUZOVUxMKENBU1QoQUNUSVZFIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKEN" ascii  
    $s7  = "yOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCUyOCcuJHBvbGUuJyUyQzB4MjclMkMweDdlJTI5KycuJGZyb20" ascii  
    $s8  = "vdW50JTI4KiUyOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCUyODB4N2UlMkMweDI3JTJDY291bnQoKiklMkM" ascii  
    $s9  = "vaHR0cDovL20ubG9hZGluZy5zZS9uZXdzLnBocD9wdWJfaWQ9NDE5MjAxMTExMTExMTExMTExMTExMTExMTExMTExMSUyMFVOSU9OJTIwU0VMRUNUJTIwMSwyLDMsNCw" ascii  
    $s10 = "BU1QoQUdFTlRfSU5URVJWQUwgQVMgQ0hBUiksJyAnKSwnanphcnF0JyxJRk5VTEwoQ0FTVChEQVRFX0NIRUNLIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKEN" ascii  
                    $s15 = "raW5va2x1Ym5pY2hrYS5ydS9uZXdzX3ZpZXcucGhwP25ld3NfaWQ9MiBVTklPTiBBTEwgU0VMRUNUIChTRUxFQ1QgQ09OQ0FUKCdxdmtxcScsSUZOVUxMKENBU1QoQUN" ascii  
    $s16 = "oc2VsZWN0K2xlbmd0aCgnLiR2YWx1ZS4nKSsnLiRmcm9tIC4nKycuJHdoZXJlLicrbGltaXQrJy4kbGltaXQuJyksQ0hBUignLiR0aGlzLT5jaGFyY2hlcigifCIpLic" ascii  
    $s17 = "ldFsnc2xlZXAnXVsnZmx0J11bJ3NwJ118fCR0aGlzLT5zZXRbJ3NsZWVwJ11bJ2ZsdCddWydhbiddKSR0aGlzLT5zZXRbJ3NsZWVwJ11bJ2ZsdCddWyd0cCddPXRydWU" ascii  
    $s18 = "JJG5ld19jaGVjayA9ICRuZXdfY2hlY2suIiUyZioqJTJmY09uVmVSdChpbnQlMmMoY2hhcigzMyklMmJjaGFyKDEyNiklMmJjaGFyKDMzKSUyYihjaGFyKDY1KSUyYmN" ascii  
    $s19 = "ST00raW5mb3JtYXRpb25fc2NoZW1hLnNjaGVtYXRhK0xJTUlUKzEpKStmcm9tK2luZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMrbGltaXQrMCwxKSxmbG9vcihyYW5kKDA" ascii  
    $s20 = "hc3Qoc2NoZW1hX25hbWUgYXMgY2hhcikpKSwweDI3LDB4N2UpIGZyb20gYGluZm9ybWF0aW9uX3NjaGVtYWAuc2NoZW1hdGEgbGltaXQgNCwxKSwweDMxMzAzMjM1MzQ" ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1000KB and
      (8 of them)
    ) or (all of them)
}