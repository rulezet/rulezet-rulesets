rule TTP_XOR_WriteProcessMemory_3168 {
  strings:
    $key_3168 = { 66 1a [2] 54 38 [2] 52 0d [2] 7c 0d [2] 43 11 }

  condition:
    any of them
}