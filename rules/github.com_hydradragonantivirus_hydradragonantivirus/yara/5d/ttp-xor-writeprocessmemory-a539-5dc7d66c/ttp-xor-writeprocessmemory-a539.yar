rule TTP_XOR_WriteProcessMemory_a539 {
  strings:
    $key_a539 = { f2 4b [2] c0 69 [2] c6 5c [2] e8 5c [2] d7 40 }

  condition:
    any of them
}