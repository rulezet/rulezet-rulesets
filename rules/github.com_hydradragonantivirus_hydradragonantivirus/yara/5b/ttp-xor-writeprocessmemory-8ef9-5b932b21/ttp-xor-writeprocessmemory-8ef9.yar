rule TTP_XOR_WriteProcessMemory_8ef9 {
  strings:
    $key_8ef9 = { d9 8b [2] eb a9 [2] ed 9c [2] c3 9c [2] fc 80 }

  condition:
    any of them
}