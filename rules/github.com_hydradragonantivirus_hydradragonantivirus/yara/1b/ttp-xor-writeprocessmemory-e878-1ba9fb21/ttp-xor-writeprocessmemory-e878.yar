rule TTP_XOR_WriteProcessMemory_e878 {
  strings:
    $key_e878 = { bf 0a [2] 8d 28 [2] 8b 1d [2] a5 1d [2] 9a 01 }

  condition:
    any of them
}