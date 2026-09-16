rule TTP_XOR_WriteProcessMemory_5a17 {
  strings:
    $key_5a17 = { 0d 65 [2] 3f 47 [2] 39 72 [2] 17 72 [2] 28 6e }

  condition:
    any of them
}