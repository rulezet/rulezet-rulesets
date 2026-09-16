import "hash"
rule IOC_NA_doc {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 14:54:58"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "doc"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "44b2f311eaba2e49b175ac9126fdcee092b1bfce3f7d5581a615c80afcfd0d1a" or
    hash.sha256(0, filesize) == "54376ee15cca7c6cdecc27b701b85bdd2aa618fe8158a453d65030425154299a" or
    hash.sha256(0, filesize) == "d8a012a24aa805042bc416d6d72694d6c3c0b726b571f5ef57ecab8690b87b99" or
    hash.sha256(0, filesize) == "976c4fdf5120d4a6e6b5d1cd26d70244fb788ea1cb50031a129ea8da9509f86a" or
    hash.sha256(0, filesize) == "69f1ebe7c4fafa1798aa4ccdc52785e5015456e2837b9a234031884f196fda62" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}