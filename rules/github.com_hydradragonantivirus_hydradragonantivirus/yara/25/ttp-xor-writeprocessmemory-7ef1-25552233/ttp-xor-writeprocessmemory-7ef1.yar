rule TTP_XOR_WriteProcessMemory_7ef1 {
  strings:
    $key_7ef1 = { 29 83 [2] 1b a1 [2] 1d 94 [2] 33 94 [2] 0c 88 }

  condition:
    any of them
}