rule TTP_XOR_WriteProcessMemory_1b11 {
  strings:
    $key_1b11 = { 4c 63 [2] 7e 41 [2] 78 74 [2] 56 74 [2] 69 68 }

  condition:
    any of them
}