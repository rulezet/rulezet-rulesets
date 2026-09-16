rule TTP_XOR_WriteProcessMemory_1c47 {
  strings:
    $key_1c47 = { 4b 35 [2] 79 17 [2] 7f 22 [2] 51 22 [2] 6e 3e }

  condition:
    any of them
}