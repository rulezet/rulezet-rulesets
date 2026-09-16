rule TTP_XOR_WriteProcessMemory_8271 {
  strings:
    $key_8271 = { d5 03 [2] e7 21 [2] e1 14 [2] cf 14 [2] f0 08 }

  condition:
    any of them
}