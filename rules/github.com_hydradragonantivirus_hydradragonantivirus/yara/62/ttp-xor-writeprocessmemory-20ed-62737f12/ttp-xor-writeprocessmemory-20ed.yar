rule TTP_XOR_WriteProcessMemory_20ed {
  strings:
    $key_20ed = { 77 9f [2] 45 bd [2] 43 88 [2] 6d 88 [2] 52 94 }

  condition:
    any of them
}