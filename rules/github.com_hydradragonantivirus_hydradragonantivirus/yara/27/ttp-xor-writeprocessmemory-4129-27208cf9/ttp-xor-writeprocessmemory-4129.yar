rule TTP_XOR_WriteProcessMemory_4129 {
  strings:
    $key_4129 = { 16 5b [2] 24 79 [2] 22 4c [2] 0c 4c [2] 33 50 }

  condition:
    any of them
}