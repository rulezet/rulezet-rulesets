rule TTP_XOR_WriteProcessMemory_17ed {
  strings:
    $key_17ed = { 40 9f [2] 72 bd [2] 74 88 [2] 5a 88 [2] 65 94 }

  condition:
    any of them
}