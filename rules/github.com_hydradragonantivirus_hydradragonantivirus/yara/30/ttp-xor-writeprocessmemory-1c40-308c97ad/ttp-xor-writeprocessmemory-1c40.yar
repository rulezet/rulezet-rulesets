rule TTP_XOR_WriteProcessMemory_1c40 {
  strings:
    $key_1c40 = { 4b 32 [2] 79 10 [2] 7f 25 [2] 51 25 [2] 6e 39 }

  condition:
    any of them
}