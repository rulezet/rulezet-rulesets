rule TTP_XOR_WriteProcessMemory_bd76 {
  strings:
    $key_bd76 = { ea 04 [2] d8 26 [2] de 13 [2] f0 13 [2] cf 0f }

  condition:
    any of them
}