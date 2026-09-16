rule TTP_XOR_WriteProcessMemory_0a07 {
  strings:
    $key_0a07 = { 5d 75 [2] 6f 57 [2] 69 62 [2] 47 62 [2] 78 7e }

  condition:
    any of them
}