rule sig_20160526_a9a88cb7b5fd14e4c6cbc31fcef0eaec {
  meta:
    description = "datamaliciousorder - file 20160526_a9a88cb7b5fd14e4c6cbc31fcef0eaec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e49075eff212d6548123ef616857c9fe372bd86eacdd6b5185bd9749f3d7bb7"

  strings:
    $s1 = "STAW rav\\n\\r;]1rDSTVZH+yERDIEE+hPPMOEX + 7sSZO+))(};dHQVKVL nruter{)(yFRV noitcnuf(+lBHOBZI+))(};tKUP nruter{)(4eHUU noitcnuf(" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}