rule TTP_XOR_WriteProcessMemory_6cf1 {
  strings:
    $key_6cf1 = { 3b 83 [2] 09 a1 [2] 0f 94 [2] 21 94 [2] 1e 88 }

  condition:
    any of them
}