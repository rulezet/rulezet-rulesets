rule TTP_XOR_WriteProcessMemory_24c3 {
  strings:
    $key_24c3 = { 73 b1 [2] 41 93 [2] 47 a6 [2] 69 a6 [2] 56 ba }

  condition:
    any of them
}