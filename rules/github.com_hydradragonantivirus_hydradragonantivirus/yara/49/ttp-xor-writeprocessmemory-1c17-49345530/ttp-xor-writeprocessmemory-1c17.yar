rule TTP_XOR_WriteProcessMemory_1c17 {
  strings:
    $key_1c17 = { 4b 65 [2] 79 47 [2] 7f 72 [2] 51 72 [2] 6e 6e }

  condition:
    any of them
}