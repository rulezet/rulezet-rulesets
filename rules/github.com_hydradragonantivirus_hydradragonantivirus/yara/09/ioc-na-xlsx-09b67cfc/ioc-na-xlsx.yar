import "hash"
rule IOC_NA_xlsx {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 18:46:34"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "xlsx"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "ad208fe787c74f455a317a5050c3462c8236ed6e3c58f9c6082147ca09902335" or
    hash.sha256(0, filesize) == "e583e248ba55bfc925e3ea9bb9f45bbf4473b87cdec850a62dff5f25f4945dff" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}