rule TTP_XOR_WriteProcessMemory_4c40 {
  strings:
    $key_4c40 = { 1b 32 [2] 29 10 [2] 2f 25 [2] 01 25 [2] 3e 39 }

  condition:
    any of them
}