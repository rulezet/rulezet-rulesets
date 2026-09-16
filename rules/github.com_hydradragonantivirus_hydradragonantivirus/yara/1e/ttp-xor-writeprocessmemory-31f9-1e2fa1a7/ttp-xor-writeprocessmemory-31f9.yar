rule TTP_XOR_WriteProcessMemory_31f9 {
  strings:
    $key_31f9 = { 66 8b [2] 54 a9 [2] 52 9c [2] 7c 9c [2] 43 80 }

  condition:
    any of them
}