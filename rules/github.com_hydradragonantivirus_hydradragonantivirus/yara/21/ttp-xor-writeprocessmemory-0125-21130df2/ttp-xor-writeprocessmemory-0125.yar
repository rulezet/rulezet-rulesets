rule TTP_XOR_WriteProcessMemory_0125 {
  strings:
    $key_0125 = { 56 57 [2] 64 75 [2] 62 40 [2] 4c 40 [2] 73 5c }

  condition:
    any of them
}