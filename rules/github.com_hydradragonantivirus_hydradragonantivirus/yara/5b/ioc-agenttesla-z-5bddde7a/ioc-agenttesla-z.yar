import "hash"
rule IOC_AGENTTESLA_z {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 12:24:08"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "z"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "f225748d809c050133e79a599b01e18472d8bd66591e679c54e66c2b33c43509" or
    hash.sha256(0, filesize) == "7a8f27f3ad544c3c482f04e8fcb92fdeb4d19250228b3522ad4490aad2ae4b8d" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}