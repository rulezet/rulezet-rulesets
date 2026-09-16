rule RUSSIANPANDA_Obfuscation_Powershell_Special_Chars {
  meta:
    description = "Detects PowerShell special character obfuscation"
    author      = "RussianPanda"
    id          = "dd2d41d4-3431-5252-adf1-d537f3b8db7e"
    date        = "2024-01-12"
    modified    = "2024-02-02"
    reference   = "https://perl-users.jp/articles/advent-calendar/2010/sym/11"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/PowerShell Obfuscation/obfuscation_powershell_special_chars.yar#L1-L15"
    license_url = "N/A"
    hash        = "d77efad78ef3afc5426432597ba129141952719846bc5ccd058249bb23d8a905"
    logic_hash  = "4cc4ebffe7bf712b412a060536acc51d94381d24b46e5494195ae17482076cd6"
    score       = 75
    quality     = 81
    tags        = ""

  strings:
    $s1 = "}=++${"
    $s2 = "$(  )"
    $s3 = { 24 7B [1-10] 7D 20 20 2B 20 20 24 }
    $s4 = { 24 7B [1-10] 7D 24 7B }

  condition:
    2 of ($s*)
}