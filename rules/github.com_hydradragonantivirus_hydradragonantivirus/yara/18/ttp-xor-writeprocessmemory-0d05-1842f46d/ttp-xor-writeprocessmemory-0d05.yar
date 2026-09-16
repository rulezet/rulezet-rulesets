rule TTP_XOR_WriteProcessMemory_0d05 {
  strings:
    $key_0d05 = { 5a 77 [2] 68 55 [2] 6e 60 [2] 40 60 [2] 7f 7c }

  condition:
    any of them
}