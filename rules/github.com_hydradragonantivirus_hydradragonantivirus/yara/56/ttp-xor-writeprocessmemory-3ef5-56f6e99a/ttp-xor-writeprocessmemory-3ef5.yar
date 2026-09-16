rule TTP_XOR_WriteProcessMemory_3ef5 {
  strings:
    $key_3ef5 = { 69 87 [2] 5b a5 [2] 5d 90 [2] 73 90 [2] 4c 8c }

  condition:
    any of them
}