rule ARKBIRD_SOLG_UNK_DEV_0322_Jul_2021_1: CVE_2021_35211 FILE {
  meta:
    description = "Detect the script used by DEV-0322 for create a new user after exploit the CVE-2021-35211"
    author      = "Arkbird_SOLG"
    id          = "8d16eb7f-c137-5f23-8830-ce26dc6e4d52"
    date        = "2021-07-16"
    modified    = "2021-11-10"
    reference   = "https://www.cadosecurity.com/triage-analysis-of-serv-u-ftp-user-backdoor-deployed-by-cve-2021-35211/"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-11-09/DEV_0322/UNK_DEV_0322_Jul_2021_1.yara#L1-L26"
    license_url = "N/A"
    logic_hash  = "7d7f012053bff6217f0fe9087acbeba13f83cb2c3dbe9a4fe8e7e0e4551edefd"
    score       = 75
    quality     = 59
    tags        = "CVE-2021-35211, FILE"
    hash1       = "fb101d9980ba2e22dceac7367c670b4894eaae9a8cef9de98ed85499a3b014ea"
    hash2       = "134a570f480536d04a056da99e58a3c982aa36f5b314f48a01420b66b759d35d"
    hash3       = "8785f1049eed4f837e634bf61468e6db921368b61ef5c8b4afa03f44465bd3e0"
    tlp         = "white"
    adversary   = "DEV-0322"

  strings:
    $obj1 = "ActiveXObject('Scripting.FileSystemObject')"
    $obj2 = "ActiveXObject(\"WScript.Shell\")"
    $arg1 = "-stopengine"
    $arg2 = "-startservice"
    $s1   = "<<- AdminType"
    $s2   = "CUserPasswordAttr\\r\\nPassword"
    $s3   = "<<- PasswordChangedOn\\r\\nCRhinoUintAttr"
    $s4   = "<<- IncludeRespCodesInMsgFiles"

  condition:
    filesize > 1KB and filesize < 15KB and all of ($obj*) and all of ($arg*) and 3 of ($s*)
}