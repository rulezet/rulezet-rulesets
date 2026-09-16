rule TTP_XOR_WriteProcessMemory_53ed {
  strings:
    $key_53ed = { 04 9f [2] 36 bd [2] 30 88 [2] 1e 88 [2] 21 94 }

  condition:
    any of them
}