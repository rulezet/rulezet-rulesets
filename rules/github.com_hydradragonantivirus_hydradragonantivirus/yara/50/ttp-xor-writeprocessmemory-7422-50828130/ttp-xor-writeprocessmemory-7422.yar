rule TTP_XOR_WriteProcessMemory_7422 {
  strings:
    $key_7422 = { 23 50 [2] 11 72 [2] 17 47 [2] 39 47 [2] 06 5b }

  condition:
    any of them
}