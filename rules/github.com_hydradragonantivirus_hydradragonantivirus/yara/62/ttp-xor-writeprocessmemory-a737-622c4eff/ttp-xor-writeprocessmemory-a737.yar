rule TTP_XOR_WriteProcessMemory_a737 {
  strings:
    $key_a737 = { f0 45 [2] c2 67 [2] c4 52 [2] ea 52 [2] d5 4e }

  condition:
    any of them
}