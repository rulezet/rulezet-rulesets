rule TTP_XOR_WriteProcessMemory_e153 {
  strings:
    $key_e153 = { b6 21 [2] 84 03 [2] 82 36 [2] ac 36 [2] 93 2a }

  condition:
    any of them
}