rule TTP_XOR_WriteProcessMemory_e1e9 {
  strings:
    $key_e1e9 = { b6 9b [2] 84 b9 [2] 82 8c [2] ac 8c [2] 93 90 }

  condition:
    any of them
}