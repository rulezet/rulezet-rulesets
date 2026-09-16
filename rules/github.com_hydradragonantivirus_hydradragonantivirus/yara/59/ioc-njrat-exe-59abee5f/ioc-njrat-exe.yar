import "hash"
rule IOC_NJRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NJRAT_LAB"
    date_IOC   = "2023-11-15 03:31:26"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NJRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "dd1200655c6acff2c7a4d4d3a0c86399a9f23823535e9e6224860a521f360678" or
    hash.sha256(0, filesize) == "ac8753ced58a7ac1ee13dc6de9f1007cdc10e9be93e398f4fa64689f2ff22ae7" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}