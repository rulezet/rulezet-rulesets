rule TTP_XOR_WriteProcessMemory_06d0 {
  strings:
    $key_06d0 = { 51 a2 [2] 63 80 [2] 65 b5 [2] 4b b5 [2] 74 a9 }

  condition:
    any of them
}