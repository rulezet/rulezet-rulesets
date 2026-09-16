import "pe"
rule sig_6898_dcrypt {
  meta:
    description = "6898 - file dcrypt.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-11-14"
    hash1       = "02ac3a4f1cfb2723c20f3c7678b62c340c7974b95f8d9320941641d5c6fd2fee"

  strings:
    $s1  = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
    $s2  = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
    $s3  = "Prevents the user from cancelling during the installation process." fullword wide
    $s4  = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
    $s5  = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
    $s6  = "/PASSWORD=password" fullword wide
    $s7  = "The Setup program accepts optional command line parameters." fullword wide
    $s8  = "Overrides the default component settings." fullword wide
    $s9  = "Specifies the password to use." fullword wide
    $s10 = "/MERGETASKS=\"comma separated list of task names\"" fullword wide
    $s11 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide
    $s12 = "/DIR=\"x:\\dirname\"" fullword wide
    $s13 = "http://diskcryptor.org/                                     " fullword wide
    $s14 = "Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requ" wide
    $s15 = "HBPLg.sse" fullword ascii
    $s16 = "/LOG=\"filename\"" fullword wide
    $s17 = "Overrides the default folder name." fullword wide
    $s18 = "Overrides the default setup type." fullword wide
    $s19 = "Overrides the default directory name." fullword wide
    $s20 = "* AVz'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and
    (pe.imphash() == "48aa5c8931746a9655524f67b25a47ef" and all of them)
}