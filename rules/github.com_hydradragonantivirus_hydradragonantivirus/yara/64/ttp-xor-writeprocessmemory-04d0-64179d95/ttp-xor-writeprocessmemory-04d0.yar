rule TTP_XOR_WriteProcessMemory_04d0 {
  strings:
    $key_04d0 = { 53 a2 [2] 61 80 [2] 67 b5 [2] 49 b5 [2] 76 a9 }

  condition:
    any of them
}