rule TTP_XOR_WriteProcessMemory_1b47 {
  strings:
    $key_1b47 = { 4c 35 [2] 7e 17 [2] 78 22 [2] 56 22 [2] 69 3e }

  condition:
    any of them
}