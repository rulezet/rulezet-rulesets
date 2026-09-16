rule TTP_XOR_WriteProcessMemory_2151 {
  strings:
    $key_2151 = { 76 23 [2] 44 01 [2] 42 34 [2] 6c 34 [2] 53 28 }

  condition:
    any of them
}