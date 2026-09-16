rule TTP_XOR_WriteProcessMemory_30ed {
  strings:
    $key_30ed = { 67 9f [2] 55 bd [2] 53 88 [2] 7d 88 [2] 42 94 }

  condition:
    any of them
}