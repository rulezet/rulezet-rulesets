rule TTP_XOR_WriteProcessMemory_0c32 {
  strings:
    $key_0c32 = { 5b 40 [2] 69 62 [2] 6f 57 [2] 41 57 [2] 7e 4b }

  condition:
    any of them
}