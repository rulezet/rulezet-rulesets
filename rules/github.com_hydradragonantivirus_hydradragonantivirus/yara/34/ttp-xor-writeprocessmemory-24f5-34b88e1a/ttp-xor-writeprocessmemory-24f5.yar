rule TTP_XOR_WriteProcessMemory_24f5 {
  strings:
    $key_24f5 = { 73 87 [2] 41 a5 [2] 47 90 [2] 69 90 [2] 56 8c }

  condition:
    any of them
}