rule TTP_XOR_WriteProcessMemory_08dd {
  strings:
    $key_08dd = { 5f af [2] 6d 8d [2] 6b b8 [2] 45 b8 [2] 7a a4 }

  condition:
    any of them
}