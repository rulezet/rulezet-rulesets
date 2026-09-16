rule TTP_XOR_WriteProcessMemory_a4ee {
  strings:
    $key_a4ee = { f3 9c [2] c1 be [2] c7 8b [2] e9 8b [2] d6 97 }

  condition:
    any of them
}