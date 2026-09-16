rule TTP_XOR_WriteProcessMemory_a771 {
  strings:
    $key_a771 = { f0 03 [2] c2 21 [2] c4 14 [2] ea 14 [2] d5 08 }

  condition:
    any of them
}