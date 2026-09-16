rule TTP_XOR_WriteProcessMemory_4c61 {
  strings:
    $key_4c61 = { 1b 13 [2] 29 31 [2] 2f 04 [2] 01 04 [2] 3e 18 }

  condition:
    any of them
}