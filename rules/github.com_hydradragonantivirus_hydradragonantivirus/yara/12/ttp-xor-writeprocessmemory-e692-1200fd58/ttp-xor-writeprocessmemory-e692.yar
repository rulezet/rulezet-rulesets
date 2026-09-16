rule TTP_XOR_WriteProcessMemory_e692 {
  strings:
    $key_e692 = { b1 e0 [2] 83 c2 [2] 85 f7 [2] ab f7 [2] 94 eb }

  condition:
    any of them
}