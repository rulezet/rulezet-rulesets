rule TTP_XOR_WriteProcessMemory_a001 {
  strings:
    $key_a001 = { f7 73 [2] c5 51 [2] c3 64 [2] ed 64 [2] d2 78 }

  condition:
    any of them
}