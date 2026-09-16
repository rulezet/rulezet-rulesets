rule TTP_XOR_WriteProcessMemory_4b65 {
  strings:
    $key_4b65 = { 1c 17 [2] 2e 35 [2] 28 00 [2] 06 00 [2] 39 1c }

  condition:
    any of them
}