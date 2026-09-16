rule TTP_XOR_WriteProcessMemory_3268 {
  strings:
    $key_3268 = { 65 1a [2] 57 38 [2] 51 0d [2] 7f 0d [2] 40 11 }

  condition:
    any of them
}