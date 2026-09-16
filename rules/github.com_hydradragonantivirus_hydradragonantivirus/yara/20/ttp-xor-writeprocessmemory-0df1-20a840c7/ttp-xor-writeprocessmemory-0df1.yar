rule TTP_XOR_WriteProcessMemory_0df1 {
  strings:
    $key_0df1 = { 5a 83 [2] 68 a1 [2] 6e 94 [2] 40 94 [2] 7f 88 }

  condition:
    any of them
}