rule TTP_XOR_WriteProcessMemory_1b67 {
  strings:
    $key_1b67 = { 4c 15 [2] 7e 37 [2] 78 02 [2] 56 02 [2] 69 1e }

  condition:
    any of them
}