rule TTP_XOR_WriteProcessMemory_8266 {
  strings:
    $key_8266 = { d5 14 [2] e7 36 [2] e1 03 [2] cf 03 [2] f0 1f }

  condition:
    any of them
}