rule TTP_XOR_WriteProcessMemory_3aa3 {
  strings:
    $key_3aa3 = { 6d d1 [2] 5f f3 [2] 59 c6 [2] 77 c6 [2] 48 da }

  condition:
    any of them
}