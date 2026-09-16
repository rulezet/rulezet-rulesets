rule TTP_XOR_WriteProcessMemory_a509 {
  strings:
    $key_a509 = { f2 7b [2] c0 59 [2] c6 6c [2] e8 6c [2] d7 70 }

  condition:
    any of them
}