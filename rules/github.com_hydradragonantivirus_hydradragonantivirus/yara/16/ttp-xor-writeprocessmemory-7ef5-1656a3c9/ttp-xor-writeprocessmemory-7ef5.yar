rule TTP_XOR_WriteProcessMemory_7ef5 {
  strings:
    $key_7ef5 = { 29 87 [2] 1b a5 [2] 1d 90 [2] 33 90 [2] 0c 8c }

  condition:
    any of them
}