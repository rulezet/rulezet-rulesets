rule TTP_XOR_WriteProcessMemory_3c17 {
  strings:
    $key_3c17 = { 6b 65 [2] 59 47 [2] 5f 72 [2] 71 72 [2] 4e 6e }

  condition:
    any of them
}