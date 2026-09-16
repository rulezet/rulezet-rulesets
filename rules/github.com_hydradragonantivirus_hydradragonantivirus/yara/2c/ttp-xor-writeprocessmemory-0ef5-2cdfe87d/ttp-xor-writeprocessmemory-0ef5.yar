rule TTP_XOR_WriteProcessMemory_0ef5 {
  strings:
    $key_0ef5 = { 59 87 [2] 6b a5 [2] 6d 90 [2] 43 90 [2] 7c 8c }

  condition:
    any of them
}