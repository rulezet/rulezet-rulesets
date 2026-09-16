rule TTP_XOR_WriteProcessMemory_0145 {
  strings:
    $key_0145 = { 56 37 [2] 64 15 [2] 62 20 [2] 4c 20 [2] 73 3c }

  condition:
    any of them
}