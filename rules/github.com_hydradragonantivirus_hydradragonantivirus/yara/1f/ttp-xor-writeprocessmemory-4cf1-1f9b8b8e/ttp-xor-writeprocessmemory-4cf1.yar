rule TTP_XOR_WriteProcessMemory_4cf1 {
  strings:
    $key_4cf1 = { 1b 83 [2] 29 a1 [2] 2f 94 [2] 01 94 [2] 3e 88 }

  condition:
    any of them
}