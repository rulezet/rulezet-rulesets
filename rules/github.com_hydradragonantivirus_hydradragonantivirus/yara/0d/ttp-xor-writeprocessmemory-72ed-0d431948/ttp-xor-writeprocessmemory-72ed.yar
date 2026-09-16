rule TTP_XOR_WriteProcessMemory_72ed {
  strings:
    $key_72ed = { 25 9f [2] 17 bd [2] 11 88 [2] 3f 88 [2] 00 94 }

  condition:
    any of them
}