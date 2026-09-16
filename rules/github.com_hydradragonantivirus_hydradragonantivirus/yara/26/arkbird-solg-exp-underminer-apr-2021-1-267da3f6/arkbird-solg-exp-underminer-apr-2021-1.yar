rule ARKBIRD_SOLG_Exp_Underminer_Apr_2021_1: FILE {
  meta:
    description = "Detect Underminer exploit kit"
    author      = "Arkbird_SOLG"
    id          = "bd2a6b30-e05a-5f90-8dc2-719c1ba48a61"
    date        = "2021-04-14"
    modified    = "2021-04-15"
    reference   = "https://twitter.com/nao_sec/status/1382358986813415427"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-04-14/Underminer/Exp_Underminer_Apr_2021_1.yar#L1-L20"
    license_url = "N/A"
    logic_hash  = "46dd4d8ba58e79761056d3dd6921530520b0071090bcfc3bfaed7a6804f787b7"
    score       = 75
    quality     = 63
    tags        = "FILE"
    hash1       = "172ac73cda6260918510ad2f4481a7fcd90c5a86d47dd880c5bcb3596dd20a7d"

  strings:
    $s1 = "new ActiveXObject(\"ShockwaveFlash.ShockwaveFlash\")"
    $s2 = "$version" fullword ascii
    $s3 = "navigator.plugins&&navigator.plugins.length>0"
    $s4 = "navigator.plugins[\"Shockwave Flash\"]"
    $s5 = "classid='clsid:D27CDB6E-AE6D-11cf-96B8-444553540000'"
    $s6 = "\"application/x-shockwave-flash\""
    $s7 = "\"data\",\"/logo.swf\""
    $s8 = { 22 30 30 30 30 30 30 30 30 22 2b 28 [1-8] 5b 30 5d 3e 3e 3e 30 29 2e 74 6f 53 74 72 69 6e 67 28 31 36 29 29 2e 73 6c 69 63 65 28 2d 38 29 2b 28 22 30 30 30 30 30 30 30 30 22 2b 28 [1-8] 5b 31 5d 3e 3e 3e 30 29 2e 74 6f 53 74 72 69 6e 67 28 31 36 29 29 2e 73 6c 69 63 65 28 2d 38 29 }

  condition:
    filesize > 5KB and 6 of ($s*)
}