rule TTP_XOR_WriteProcessMemory_a735 {
  strings:
    $key_a735 = { f0 47 [2] c2 65 [2] c4 50 [2] ea 50 [2] d5 4c }

  condition:
    any of them
}