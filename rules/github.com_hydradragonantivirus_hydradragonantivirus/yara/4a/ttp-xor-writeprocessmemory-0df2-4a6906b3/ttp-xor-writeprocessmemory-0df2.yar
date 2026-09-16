rule TTP_XOR_WriteProcessMemory_0df2 {
  strings:
    $key_0df2 = { 5a 80 [2] 68 a2 [2] 6e 97 [2] 40 97 [2] 7f 8b }

  condition:
    any of them
}