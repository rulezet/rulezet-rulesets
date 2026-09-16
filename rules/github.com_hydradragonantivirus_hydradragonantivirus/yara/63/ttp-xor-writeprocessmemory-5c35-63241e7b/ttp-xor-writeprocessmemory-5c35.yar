rule TTP_XOR_WriteProcessMemory_5c35 {
  strings:
    $key_5c35 = { 0b 47 [2] 39 65 [2] 3f 50 [2] 11 50 [2] 2e 4c }

  condition:
    any of them
}