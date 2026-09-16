rule TTP_XOR_WriteProcessMemory_06f0 {
  strings:
    $key_06f0 = { 51 82 [2] 63 a0 [2] 65 95 [2] 4b 95 [2] 74 89 }

  condition:
    any of them
}