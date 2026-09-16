rule TTP_XOR_WriteProcessMemory_b129 {
  strings:
    $key_b129 = { e6 5b [2] d4 79 [2] d2 4c [2] fc 4c [2] c3 50 }

  condition:
    any of them
}