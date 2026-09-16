import "hash"
rule IOC_MIRAI_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_MIRAI_LAB"
    date_IOC   = "2023-11-14 06:10:22"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "MIRAI"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "c8112fddbfed0adfa62343a770dc09984c306063cfe01e4989f8a96893fdb908" or
    hash.sha256(0, filesize) == "0e9ec7fffe192bb53a79d9a71ba74884bc9493cc55c6e363e7ad952c53da25fe" or
    hash.sha256(0, filesize) == "eec68e0190cb6b7683556b3fde3922936b0b0a70d0efd2062c53c87f2adfdb1f" or
    hash.sha256(0, filesize) == "0433abed1161da8a9c18a8855f9a65d9dd2ce66392107e989e058e510033f26e" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}