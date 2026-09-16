rule TTP_XOR_WriteProcessMemory_3521 {
  strings:
    $key_3521 = { 62 53 [2] 50 71 [2] 56 44 [2] 78 44 [2] 47 58 }

  condition:
    any of them
}