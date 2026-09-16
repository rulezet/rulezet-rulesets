import "hash"
rule IOC_FORMBOOK___ace_ {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_FORMBOOK_LAB"
    date_IOC   = "2023-11-15 07:38:59"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "FORMBOOK"
    file_type  = "__ace_"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "4b0088a5ea5b554b183064229db63803bac5538cd7cb9f5f1092e50dce0d4ade" or
    hash.sha256(0, filesize) == "7d3b00a4fcda70ad6620192068b141cc01d43f1d4ed650ddd65593cb24f7f9c1" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}