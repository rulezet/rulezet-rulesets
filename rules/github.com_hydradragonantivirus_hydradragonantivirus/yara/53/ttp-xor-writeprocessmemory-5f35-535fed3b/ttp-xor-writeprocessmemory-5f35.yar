rule TTP_XOR_WriteProcessMemory_5f35 {
  strings:
    $key_5f35 = { 08 47 [2] 3a 65 [2] 3c 50 [2] 12 50 [2] 2d 4c }

  condition:
    any of them
}