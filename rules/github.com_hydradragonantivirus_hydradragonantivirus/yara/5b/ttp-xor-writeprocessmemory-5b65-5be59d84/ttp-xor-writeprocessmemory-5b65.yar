rule TTP_XOR_WriteProcessMemory_5b65 {
  strings:
    $key_5b65 = { 0c 17 [2] 3e 35 [2] 38 00 [2] 16 00 [2] 29 1c }

  condition:
    any of them
}