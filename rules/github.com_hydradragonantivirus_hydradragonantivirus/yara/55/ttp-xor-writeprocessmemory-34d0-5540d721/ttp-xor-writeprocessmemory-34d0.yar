rule TTP_XOR_WriteProcessMemory_34d0 {
  strings:
    $key_34d0 = { 63 a2 [2] 51 80 [2] 57 b5 [2] 79 b5 [2] 46 a9 }

  condition:
    any of them
}