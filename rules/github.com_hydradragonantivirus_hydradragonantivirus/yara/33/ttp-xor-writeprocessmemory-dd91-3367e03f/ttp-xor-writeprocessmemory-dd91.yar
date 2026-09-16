rule TTP_XOR_WriteProcessMemory_dd91 {
  strings:
    $key_dd91 = { 8a e3 [2] b8 c1 [2] be f4 [2] 90 f4 [2] af e8 }

  condition:
    any of them
}