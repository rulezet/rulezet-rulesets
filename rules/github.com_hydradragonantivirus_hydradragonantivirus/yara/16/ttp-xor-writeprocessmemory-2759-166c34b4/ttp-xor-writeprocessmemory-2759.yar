rule TTP_XOR_WriteProcessMemory_2759 {
  strings:
    $key_2759 = { 70 2b [2] 42 09 [2] 44 3c [2] 6a 3c [2] 55 20 }

  condition:
    any of them
}