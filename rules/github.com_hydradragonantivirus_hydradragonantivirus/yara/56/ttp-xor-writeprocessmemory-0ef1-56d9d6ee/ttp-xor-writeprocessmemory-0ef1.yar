rule TTP_XOR_WriteProcessMemory_0ef1 {
  strings:
    $key_0ef1 = { 59 83 [2] 6b a1 [2] 6d 94 [2] 43 94 [2] 7c 88 }

  condition:
    any of them
}