rule TTP_XOR_WriteProcessMemory_a439 {
  strings:
    $key_a439 = { f3 4b [2] c1 69 [2] c7 5c [2] e9 5c [2] d6 40 }

  condition:
    any of them
}