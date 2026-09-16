rule TTP_XOR_WriteProcessMemory_3ef0 {
  strings:
    $key_3ef0 = { 69 82 [2] 5b a0 [2] 5d 95 [2] 73 95 [2] 4c 89 }

  condition:
    any of them
}