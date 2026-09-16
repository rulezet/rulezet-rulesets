rule TTP_XOR_WriteProcessMemory_1c67 {
  strings:
    $key_1c67 = { 4b 15 [2] 79 37 [2] 7f 02 [2] 51 02 [2] 6e 1e }

  condition:
    any of them
}