rule TTP_XOR_WriteProcessMemory_e270 {
  strings:
    $key_e270 = { b5 02 [2] 87 20 [2] 81 15 [2] af 15 [2] 90 09 }

  condition:
    any of them
}