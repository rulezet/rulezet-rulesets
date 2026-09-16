import "hash"
rule IOC_NA_unknown {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 14:20:43"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "unknown"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "2a8f9fa9e3d05c509f9858cae27a530a1cd6284c9bd4b77e12c811c28b9dadb7" or
    hash.sha256(0, filesize) == "b6702aff8b11508caf4a291f7580eeda872dd8d8d46b31bd342828fa23124e46" or
    hash.sha256(0, filesize) == "70aa5561a87f3d07e2ade10726204db619f4370632d44bd9ff2b6619e4755803" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}