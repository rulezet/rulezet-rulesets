rule TTP_XOR_WriteProcessMemory_e178 {
  strings:
    $key_e178 = { b6 0a [2] 84 28 [2] 82 1d [2] ac 1d [2] 93 01 }

  condition:
    any of them
}