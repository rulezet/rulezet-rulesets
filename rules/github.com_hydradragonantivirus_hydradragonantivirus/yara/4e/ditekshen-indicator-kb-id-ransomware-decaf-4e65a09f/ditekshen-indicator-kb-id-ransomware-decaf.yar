rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_DECAF {
  meta:
    description = "Detects files referencing identities associated with DECAF ransomware"
    author      = "ditekShen"
    id          = "24422015-56f3-503e-a902-0183eb601b22"
    date        = "2024-01-23"
    modified    = "2024-01-23"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L376-L408"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "8fca3a6564cd11e625b65e7f0f278b79678368dd0c77440e9f8d46035e0c3426"
    score       = 75
    quality     = 73
    tags        = ""

  strings:
    $s1 = "22eb687475f2c5ca30b@protonmail.com" ascii wide nocase
    $s2 = "MIIBCgKCAQEAq4k1Hdb1THrzBBeO184knCbBKr03apfXqlOkSdtHSJgfyIqJPGxl\n/cFisJmVXR3/t4e9FbLsEIuTp9PJTciomHfr5CgCQzhnAZ0AvjGBaWP6KpCyfDns\nybruyKqygaWpZSAnzRdB+TAku5iqy8q1VwnN57QBltro0YJZ8enKZRTlczmtjeOp\nB/xuTOuDjmUSNiGyijWBVfYk7sVXl/lQ8taXr36xPWhMIG0EqRVrFV+cavS7Z4va\nyXmcf55NkpMGKKY8uqvwb4aLIKabek2nUWBgNgSOtqBLLL2A2bY/5s0GJ/VV+EmI\nX7/zI+FceU+dcNX/ir0ujP4ys4m/jjZD4wIDAQAB"

  condition:
    any of them
}