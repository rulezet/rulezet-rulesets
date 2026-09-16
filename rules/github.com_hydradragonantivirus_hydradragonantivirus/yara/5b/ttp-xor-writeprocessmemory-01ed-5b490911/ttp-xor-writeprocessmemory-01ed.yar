rule TTP_XOR_WriteProcessMemory_01ed {
  strings:
    $key_01ed = { 56 9f [2] 64 bd [2] 62 88 [2] 4c 88 [2] 73 94 }

  condition:
    any of them
}