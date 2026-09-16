rule TTP_XOR_WriteProcessMemory_5aa3 {
  strings:
    $key_5aa3 = { 0d d1 [2] 3f f3 [2] 39 c6 [2] 17 c6 [2] 28 da }

  condition:
    any of them
}