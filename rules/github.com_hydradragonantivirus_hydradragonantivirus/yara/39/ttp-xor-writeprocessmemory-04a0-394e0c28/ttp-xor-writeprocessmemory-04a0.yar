rule TTP_XOR_WriteProcessMemory_04a0 {
  strings:
    $key_04a0 = { 53 d2 [2] 61 f0 [2] 67 c5 [2] 49 c5 [2] 76 d9 }

  condition:
    any of them
}