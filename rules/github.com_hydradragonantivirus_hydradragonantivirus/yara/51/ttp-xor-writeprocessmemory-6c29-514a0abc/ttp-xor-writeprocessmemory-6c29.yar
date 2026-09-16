rule TTP_XOR_WriteProcessMemory_6c29 {
  strings:
    $key_6c29 = { 3b 5b [2] 09 79 [2] 0f 4c [2] 21 4c [2] 1e 50 }

  condition:
    any of them
}