rule TTP_XOR_WriteProcessMemory_1b30 {
  strings:
    $key_1b30 = { 4c 42 [2] 7e 60 [2] 78 55 [2] 56 55 [2] 69 49 }

  condition:
    any of them
}