rule TTP_XOR_WriteProcessMemory_1759 {
  strings:
    $key_1759 = { 40 2b [2] 72 09 [2] 74 3c [2] 5a 3c [2] 65 20 }

  condition:
    any of them
}