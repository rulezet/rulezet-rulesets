rule TTP_XOR_WriteProcessMemory_e168 {
  strings:
    $key_e168 = { b6 1a [2] 84 38 [2] 82 0d [2] ac 0d [2] 93 11 }

  condition:
    any of them
}