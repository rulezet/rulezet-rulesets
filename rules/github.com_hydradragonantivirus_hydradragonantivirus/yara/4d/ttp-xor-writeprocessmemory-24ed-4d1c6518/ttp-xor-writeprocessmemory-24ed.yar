rule TTP_XOR_WriteProcessMemory_24ed {
  strings:
    $key_24ed = { 73 9f [2] 41 bd [2] 47 88 [2] 69 88 [2] 56 94 }

  condition:
    any of them
}