rule TTP_XOR_WriteProcessMemory_4c51 {
  strings:
    $key_4c51 = { 1b 23 [2] 29 01 [2] 2f 34 [2] 01 34 [2] 3e 28 }

  condition:
    any of them
}