rule TTP_XOR_WriteProcessMemory_4c60 {
  strings:
    $key_4c60 = { 1b 12 [2] 29 30 [2] 2f 05 [2] 01 05 [2] 3e 19 }

  condition:
    any of them
}