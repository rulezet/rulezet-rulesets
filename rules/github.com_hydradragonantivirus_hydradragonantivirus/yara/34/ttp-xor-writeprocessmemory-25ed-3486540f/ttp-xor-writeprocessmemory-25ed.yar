rule TTP_XOR_WriteProcessMemory_25ed {
  strings:
    $key_25ed = { 72 9f [2] 40 bd [2] 46 88 [2] 68 88 [2] 57 94 }

  condition:
    any of them
}