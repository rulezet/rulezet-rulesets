rule TTP_XOR_WriteProcessMemory_4c53 {
  strings:
    $key_4c53 = { 1b 21 [2] 29 03 [2] 2f 36 [2] 01 36 [2] 3e 2a }

  condition:
    any of them
}