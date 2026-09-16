rule TTP_XOR_WriteProcessMemory_e974 {
  strings:
    $key_e974 = { be 06 [2] 8c 24 [2] 8a 11 [2] a4 11 [2] 9b 0d }

  condition:
    any of them
}