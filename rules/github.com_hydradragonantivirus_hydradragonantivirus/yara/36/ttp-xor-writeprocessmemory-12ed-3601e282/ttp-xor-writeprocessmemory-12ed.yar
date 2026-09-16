rule TTP_XOR_WriteProcessMemory_12ed {
  strings:
    $key_12ed = { 45 9f [2] 77 bd [2] 71 88 [2] 5f 88 [2] 60 94 }

  condition:
    any of them
}