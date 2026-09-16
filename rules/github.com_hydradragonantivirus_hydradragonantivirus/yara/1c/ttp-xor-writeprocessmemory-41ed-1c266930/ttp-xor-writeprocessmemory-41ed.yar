rule TTP_XOR_WriteProcessMemory_41ed {
  strings:
    $key_41ed = { 16 9f [2] 24 bd [2] 22 88 [2] 0c 88 [2] 33 94 }

  condition:
    any of them
}