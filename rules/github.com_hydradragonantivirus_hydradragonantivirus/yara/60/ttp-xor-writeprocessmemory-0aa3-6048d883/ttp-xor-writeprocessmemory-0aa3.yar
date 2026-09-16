rule TTP_XOR_WriteProcessMemory_0aa3 {
  strings:
    $key_0aa3 = { 5d d1 [2] 6f f3 [2] 69 c6 [2] 47 c6 [2] 78 da }

  condition:
    any of them
}