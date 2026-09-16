rule TTP_XOR_WriteProcessMemory_2cf1 {
  strings:
    $key_2cf1 = { 7b 83 [2] 49 a1 [2] 4f 94 [2] 61 94 [2] 5e 88 }

  condition:
    any of them
}