rule TTP_XOR_WriteProcessMemory_a409 {
  strings:
    $key_a409 = { f3 7b [2] c1 59 [2] c7 6c [2] e9 6c [2] d6 70 }

  condition:
    any of them
}