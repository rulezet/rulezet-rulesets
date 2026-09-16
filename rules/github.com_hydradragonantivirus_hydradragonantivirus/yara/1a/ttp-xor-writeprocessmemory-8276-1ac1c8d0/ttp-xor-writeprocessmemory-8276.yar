rule TTP_XOR_WriteProcessMemory_8276 {
  strings:
    $key_8276 = { d5 04 [2] e7 26 [2] e1 13 [2] cf 13 [2] f0 0f }

  condition:
    any of them
}