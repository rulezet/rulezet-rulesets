rule TTP_XOR_WriteProcessMemory_3ef1 {
  strings:
    $key_3ef1 = { 69 83 [2] 5b a1 [2] 5d 94 [2] 73 94 [2] 4c 88 }

  condition:
    any of them
}