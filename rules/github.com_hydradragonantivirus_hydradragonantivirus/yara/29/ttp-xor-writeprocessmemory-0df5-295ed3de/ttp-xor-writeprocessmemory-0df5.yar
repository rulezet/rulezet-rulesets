rule TTP_XOR_WriteProcessMemory_0df5 {
  strings:
    $key_0df5 = { 5a 87 [2] 68 a5 [2] 6e 90 [2] 40 90 [2] 7f 8c }

  condition:
    any of them
}