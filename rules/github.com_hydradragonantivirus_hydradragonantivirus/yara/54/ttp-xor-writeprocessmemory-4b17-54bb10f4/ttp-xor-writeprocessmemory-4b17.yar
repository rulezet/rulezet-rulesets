rule TTP_XOR_WriteProcessMemory_4b17 {
  strings:
    $key_4b17 = { 1c 65 [2] 2e 47 [2] 28 72 [2] 06 72 [2] 39 6e }

  condition:
    any of them
}