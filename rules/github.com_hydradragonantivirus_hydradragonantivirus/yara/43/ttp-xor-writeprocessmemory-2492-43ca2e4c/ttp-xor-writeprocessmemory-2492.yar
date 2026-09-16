rule TTP_XOR_WriteProcessMemory_2492 {
  strings:
    $key_2492 = { 73 e0 [2] 41 c2 [2] 47 f7 [2] 69 f7 [2] 56 eb }

  condition:
    any of them
}