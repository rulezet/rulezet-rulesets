rule TTP_XOR_WriteProcessMemory_0105 {
  strings:
    $key_0105 = { 56 77 [2] 64 55 [2] 62 60 [2] 4c 60 [2] 73 7c }

  condition:
    any of them
}