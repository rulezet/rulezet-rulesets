rule TTP_XOR_WriteProcessMemory_4b29 {
  strings:
    $key_4b29 = { 1c 5b [2] 2e 79 [2] 28 4c [2] 06 4c [2] 39 50 }

  condition:
    any of them
}