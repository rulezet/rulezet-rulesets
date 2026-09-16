rule TTP_XOR_WriteProcessMemory_18dd {
  strings:
    $key_18dd = { 4f af [2] 7d 8d [2] 7b b8 [2] 55 b8 [2] 6a a4 }

  condition:
    any of them
}