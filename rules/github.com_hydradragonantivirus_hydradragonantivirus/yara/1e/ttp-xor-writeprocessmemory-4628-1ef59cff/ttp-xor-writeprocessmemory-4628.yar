rule TTP_XOR_WriteProcessMemory_4628 {
  strings:
    $key_4628 = { 11 5a [2] 23 78 [2] 25 4d [2] 0b 4d [2] 34 51 }

  condition:
    any of them
}