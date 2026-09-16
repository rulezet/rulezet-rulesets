rule TTP_XOR_WriteProcessMemory_1c80 {
  strings:
    $key_1c80 = { 4b f2 [2] 79 d0 [2] 7f e5 [2] 51 e5 [2] 6e f9 }

  condition:
    any of them
}