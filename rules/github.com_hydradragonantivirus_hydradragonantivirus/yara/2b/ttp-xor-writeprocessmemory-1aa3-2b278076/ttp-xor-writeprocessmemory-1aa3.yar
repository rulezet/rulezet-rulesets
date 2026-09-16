rule TTP_XOR_WriteProcessMemory_1aa3 {
  strings:
    $key_1aa3 = { 4d d1 [2] 7f f3 [2] 79 c6 [2] 57 c6 [2] 68 da }

  condition:
    any of them
}