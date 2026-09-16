rule TTP_XOR_WriteProcessMemory_1c29 {
  strings:
    $key_1c29 = { 4b 5b [2] 79 79 [2] 7f 4c [2] 51 4c [2] 6e 50 }

  condition:
    any of them
}