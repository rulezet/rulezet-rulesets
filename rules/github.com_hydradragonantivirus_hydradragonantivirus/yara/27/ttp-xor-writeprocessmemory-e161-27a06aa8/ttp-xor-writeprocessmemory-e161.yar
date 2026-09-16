rule TTP_XOR_WriteProcessMemory_e161 {
  strings:
    $key_e161 = { b6 13 [2] 84 31 [2] 82 04 [2] ac 04 [2] 93 18 }

  condition:
    any of them
}