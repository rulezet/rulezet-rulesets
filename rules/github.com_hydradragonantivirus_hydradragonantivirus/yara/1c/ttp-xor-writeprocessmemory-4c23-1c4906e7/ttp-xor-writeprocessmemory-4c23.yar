rule TTP_XOR_WriteProcessMemory_4c23 {
  strings:
    $key_4c23 = { 1b 51 [2] 29 73 [2] 2f 46 [2] 01 46 [2] 3e 5a }

  condition:
    any of them
}