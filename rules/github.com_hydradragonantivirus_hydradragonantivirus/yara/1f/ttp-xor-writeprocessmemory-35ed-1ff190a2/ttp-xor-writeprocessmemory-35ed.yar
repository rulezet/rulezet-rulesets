rule TTP_XOR_WriteProcessMemory_35ed {
  strings:
    $key_35ed = { 62 9f [2] 50 bd [2] 56 88 [2] 78 88 [2] 47 94 }

  condition:
    any of them
}