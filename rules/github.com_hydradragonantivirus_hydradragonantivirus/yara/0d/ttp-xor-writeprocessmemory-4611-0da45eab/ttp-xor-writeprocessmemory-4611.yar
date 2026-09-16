rule TTP_XOR_WriteProcessMemory_4611 {
  strings:
    $key_4611 = { 11 63 [2] 23 41 [2] 25 74 [2] 0b 74 [2] 34 68 }

  condition:
    any of them
}