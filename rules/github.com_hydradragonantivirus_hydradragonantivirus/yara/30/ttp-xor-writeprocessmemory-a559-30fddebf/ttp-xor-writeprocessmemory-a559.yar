rule TTP_XOR_WriteProcessMemory_a559 {
  strings:
    $key_a559 = { f2 2b [2] c0 09 [2] c6 3c [2] e8 3c [2] d7 20 }

  condition:
    any of them
}