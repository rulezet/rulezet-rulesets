rule TTP_XOR_WriteProcessMemory_74ed {
  strings:
    $key_74ed = { 23 9f [2] 11 bd [2] 17 88 [2] 39 88 [2] 06 94 }

  condition:
    any of them
}