rule TTP_XOR_WriteProcessMemory_0b17 {
  strings:
    $key_0b17 = { 5c 65 [2] 6e 47 [2] 68 72 [2] 46 72 [2] 79 6e }

  condition:
    any of them
}