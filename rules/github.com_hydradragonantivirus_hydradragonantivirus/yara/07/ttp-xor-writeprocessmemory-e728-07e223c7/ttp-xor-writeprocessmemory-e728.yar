rule TTP_XOR_WriteProcessMemory_e728 {
  strings:
    $key_e728 = { b0 5a [2] 82 78 [2] 84 4d [2] aa 4d [2] 95 51 }

  condition:
    any of them
}