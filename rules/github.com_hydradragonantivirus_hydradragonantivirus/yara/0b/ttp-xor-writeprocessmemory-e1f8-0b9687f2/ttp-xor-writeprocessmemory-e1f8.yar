rule TTP_XOR_WriteProcessMemory_e1f8 {
  strings:
    $key_e1f8 = { b6 8a [2] 84 a8 [2] 82 9d [2] ac 9d [2] 93 81 }

  condition:
    any of them
}