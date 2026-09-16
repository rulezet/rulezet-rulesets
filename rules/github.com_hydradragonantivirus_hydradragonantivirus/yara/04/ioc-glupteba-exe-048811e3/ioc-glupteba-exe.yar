import "hash"
rule IOC_GLUPTEBA_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_GLUPTEBA_LAB"
    date_IOC   = "2023-11-14 03:47:09"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "GLUPTEBA"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "e26a36702257f07a25adc0e5b1a3ceeabcbcb18b63c8d83c0ccb988f848e4a08" or
    hash.sha256(0, filesize) == "7e2fc238252c47231d37ab938055672b07423ce2688bb32cff3b97dc179fee9b" or
    hash.sha256(0, filesize) == "3648e16fc4cff692d591d0074ce50481a5a3451153a875ddde85ee82dea63614" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}