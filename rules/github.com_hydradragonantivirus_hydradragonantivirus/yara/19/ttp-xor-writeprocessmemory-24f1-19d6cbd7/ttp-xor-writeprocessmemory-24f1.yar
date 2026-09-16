rule TTP_XOR_WriteProcessMemory_24f1 {
  strings:
    $key_24f1 = { 73 83 [2] 41 a1 [2] 47 94 [2] 69 94 [2] 56 88 }

  condition:
    any of them
}