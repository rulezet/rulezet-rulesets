rule TTP_XOR_WriteProcessMemory_0d75 {
  strings:
    $key_0d75 = { 5a 07 [2] 68 25 [2] 6e 10 [2] 40 10 [2] 7f 0c }

  condition:
    any of them
}