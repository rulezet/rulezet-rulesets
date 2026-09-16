rule TTP_XOR_WriteProcessMemory_5c17 {
  strings:
    $key_5c17 = { 0b 65 [2] 39 47 [2] 3f 72 [2] 11 72 [2] 2e 6e }

  condition:
    any of them
}