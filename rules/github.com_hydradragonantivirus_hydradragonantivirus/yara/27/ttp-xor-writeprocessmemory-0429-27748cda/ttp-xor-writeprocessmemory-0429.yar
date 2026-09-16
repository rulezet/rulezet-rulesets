rule TTP_XOR_WriteProcessMemory_0429 {
  strings:
    $key_0429 = { 53 5b [2] 61 79 [2] 67 4c [2] 49 4c [2] 76 50 }

  condition:
    any of them
}