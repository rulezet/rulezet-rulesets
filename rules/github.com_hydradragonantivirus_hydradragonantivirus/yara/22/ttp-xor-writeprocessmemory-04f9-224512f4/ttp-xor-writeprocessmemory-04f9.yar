rule TTP_XOR_WriteProcessMemory_04f9 {
  strings:
    $key_04f9 = { 53 8b [2] 61 a9 [2] 67 9c [2] 49 9c [2] 76 80 }

  condition:
    any of them
}