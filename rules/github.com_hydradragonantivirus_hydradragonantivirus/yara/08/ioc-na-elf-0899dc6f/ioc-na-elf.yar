import "hash"
rule IOC_NA_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-15 03:14:40"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "cd378b012d0bdef2786e3d488cee11fd34b93d1cad9339351bcbbcf6b0214017" or
    hash.sha256(0, filesize) == "3a43116d507d58f3c9717f2cb0a3d06d0c5a7dc29f601e9c2b976ee6d9c8713f" or
    hash.sha256(0, filesize) == "edc9e39acb46cb0fd23edf9df42e7b94c3f33e20c01aa3eac58f02eb95a97f76" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}