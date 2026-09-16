rule TTP_XOR_WriteProcessMemory_37ed {
  strings:
    $key_37ed = { 60 9f [2] 52 bd [2] 54 88 [2] 7a 88 [2] 45 94 }

  condition:
    any of them
}