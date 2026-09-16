rule TTP_XOR_WriteProcessMemory_e170 {
  strings:
    $key_e170 = { b6 02 [2] 84 20 [2] 82 15 [2] ac 15 [2] 93 09 }

  condition:
    any of them
}