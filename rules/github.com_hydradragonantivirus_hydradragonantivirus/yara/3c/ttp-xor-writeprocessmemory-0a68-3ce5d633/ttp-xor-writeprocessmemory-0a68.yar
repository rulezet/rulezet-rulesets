rule TTP_XOR_WriteProcessMemory_0a68 {
  strings:
    $key_0a68 = { 5d 1a [2] 6f 38 [2] 69 0d [2] 47 0d [2] 78 11 }

  condition:
    any of them
}