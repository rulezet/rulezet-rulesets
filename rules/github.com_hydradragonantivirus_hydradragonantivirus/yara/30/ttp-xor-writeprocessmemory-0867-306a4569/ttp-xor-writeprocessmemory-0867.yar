rule TTP_XOR_WriteProcessMemory_0867 {
  strings:
    $key_0867 = { 5f 15 [2] 6d 37 [2] 6b 02 [2] 45 02 [2] 7a 1e }

  condition:
    any of them
}