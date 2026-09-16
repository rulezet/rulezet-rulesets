rule TTP_XOR_WriteProcessMemory_73ed {
  strings:
    $key_73ed = { 24 9f [2] 16 bd [2] 10 88 [2] 3e 88 [2] 01 94 }

  condition:
    any of them
}