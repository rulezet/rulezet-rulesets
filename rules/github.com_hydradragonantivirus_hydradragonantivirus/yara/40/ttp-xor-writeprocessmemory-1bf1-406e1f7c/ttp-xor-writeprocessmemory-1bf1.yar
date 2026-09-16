rule TTP_XOR_WriteProcessMemory_1bf1 {
  strings:
    $key_1bf1 = { 4c 83 [2] 7e a1 [2] 78 94 [2] 56 94 [2] 69 88 }

  condition:
    any of them
}