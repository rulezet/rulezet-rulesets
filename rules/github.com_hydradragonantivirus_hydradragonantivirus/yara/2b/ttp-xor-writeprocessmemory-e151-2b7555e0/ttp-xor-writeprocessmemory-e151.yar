rule TTP_XOR_WriteProcessMemory_e151 {
  strings:
    $key_e151 = { b6 23 [2] 84 01 [2] 82 34 [2] ac 34 [2] 93 28 }

  condition:
    any of them
}