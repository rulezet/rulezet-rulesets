import "hash"
rule IOC_FORMBOOK_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-14 09:03:02"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "7be9d6679205f724ef08f8aeb900ff19e0ccc47bda06a458cf84138406056de4" or
    hash.sha256(0, filesize) == "54991e3f6afe4b0c7f2d6d43dada59b2614ce28f0af811eadf2bf7a213b13b58" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}