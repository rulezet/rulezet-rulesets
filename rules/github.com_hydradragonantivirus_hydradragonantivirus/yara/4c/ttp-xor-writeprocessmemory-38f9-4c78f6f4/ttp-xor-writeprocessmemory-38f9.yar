rule TTP_XOR_WriteProcessMemory_38f9 {
  strings:
    $key_38f9 = { 6f 8b [2] 5d a9 [2] 5b 9c [2] 75 9c [2] 4a 80 }

  condition:
    any of them
}