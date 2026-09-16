rule TTP_XOR_WriteProcessMemory_6b73 {
  strings:
    $key_6b73 = { 3c 01 [2] 0e 23 [2] 08 16 [2] 26 16 [2] 19 0a }

  condition:
    any of them
}