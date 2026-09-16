rule TTP_XOR_WriteProcessMemory_2ef1 {
  strings:
    $key_2ef1 = { 79 83 [2] 4b a1 [2] 4d 94 [2] 63 94 [2] 5c 88 }

  condition:
    any of them
}