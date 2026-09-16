rule TTP_XOR_WriteProcessMemory_a747 {
  strings:
    $key_a747 = { f0 35 [2] c2 17 [2] c4 22 [2] ea 22 [2] d5 3e }

  condition:
    any of them
}