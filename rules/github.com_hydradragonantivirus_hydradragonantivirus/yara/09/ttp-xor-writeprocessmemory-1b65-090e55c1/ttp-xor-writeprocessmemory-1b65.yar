rule TTP_XOR_WriteProcessMemory_1b65 {
  strings:
    $key_1b65 = { 4c 17 [2] 7e 35 [2] 78 00 [2] 56 00 [2] 69 1c }

  condition:
    any of them
}