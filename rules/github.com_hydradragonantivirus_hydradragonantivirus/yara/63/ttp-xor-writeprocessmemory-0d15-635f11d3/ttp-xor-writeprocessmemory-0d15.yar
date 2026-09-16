rule TTP_XOR_WriteProcessMemory_0d15 {
  strings:
    $key_0d15 = { 5a 67 [2] 68 45 [2] 6e 70 [2] 40 70 [2] 7f 6c }

  condition:
    any of them
}