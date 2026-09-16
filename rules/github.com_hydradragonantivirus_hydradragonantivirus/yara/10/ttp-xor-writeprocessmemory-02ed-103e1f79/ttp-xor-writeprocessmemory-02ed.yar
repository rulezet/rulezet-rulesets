rule TTP_XOR_WriteProcessMemory_02ed {
  strings:
    $key_02ed = { 55 9f [2] 67 bd [2] 61 88 [2] 4f 88 [2] 70 94 }

  condition:
    any of them
}