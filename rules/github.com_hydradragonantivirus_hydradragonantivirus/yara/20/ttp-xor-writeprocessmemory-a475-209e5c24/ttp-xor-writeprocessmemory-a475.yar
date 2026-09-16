rule TTP_XOR_WriteProcessMemory_a475 {
  strings:
    $key_a475 = { f3 07 [2] c1 25 [2] c7 10 [2] e9 10 [2] d6 0c }

  condition:
    any of them
}