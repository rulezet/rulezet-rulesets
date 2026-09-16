rule TTP_XOR_WriteProcessMemory_718f {
  strings:
    $key_718f = { 26 fd [2] 14 df [2] 12 ea [2] 3c ea [2] 03 f6 }

  condition:
    any of them
}