rule TTP_XOR_WriteProcessMemory_e5e9 {
  strings:
    $key_e5e9 = { b2 9b [2] 80 b9 [2] 86 8c [2] a8 8c [2] 97 90 }

  condition:
    any of them
}