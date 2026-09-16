import "hash"
rule IOC_ADWARE_NEOREKLAMI_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_ADWARE_NEOREKLAMI_LAB"
    date_IOC   = "2023-11-14 09:01:29"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "ADWARE_NEOREKLAMI"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "fd5d862f187f2b06569ceba8c3cf0960f6446904d88ec36da96cde8ba984e17b" or
    hash.sha256(0, filesize) == "5b8a371c20b16861e2dfc33f4757ffab43c79361a21099d92acda671e46d1f3d" or
    hash.sha256(0, filesize) == "7918ab26eeb714d19d3af80cc905ad014ac6e6a337d7bec51206d17a6ddb24e0" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}