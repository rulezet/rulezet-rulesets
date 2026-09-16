rule TTP_XOR_WriteProcessMemory_e7e8 {
  strings:
    $key_e7e8 = { b0 9a [2] 82 b8 [2] 84 8d [2] aa 8d [2] 95 91 }

  condition:
    any of them
}