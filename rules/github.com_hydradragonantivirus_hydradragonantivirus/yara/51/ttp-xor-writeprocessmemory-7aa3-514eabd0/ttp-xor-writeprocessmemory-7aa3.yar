rule TTP_XOR_WriteProcessMemory_7aa3 {
  strings:
    $key_7aa3 = { 2d d1 [2] 1f f3 [2] 19 c6 [2] 37 c6 [2] 08 da }

  condition:
    any of them
}