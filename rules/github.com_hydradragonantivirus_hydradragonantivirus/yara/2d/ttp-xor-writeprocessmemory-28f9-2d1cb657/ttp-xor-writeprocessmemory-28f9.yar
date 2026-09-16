rule TTP_XOR_WriteProcessMemory_28f9 {
  strings:
    $key_28f9 = { 7f 8b [2] 4d a9 [2] 4b 9c [2] 65 9c [2] 5a 80 }

  condition:
    any of them
}