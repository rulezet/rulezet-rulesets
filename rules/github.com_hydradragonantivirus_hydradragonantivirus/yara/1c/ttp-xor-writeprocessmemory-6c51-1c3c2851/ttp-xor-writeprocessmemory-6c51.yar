rule TTP_XOR_WriteProcessMemory_6c51 {
  strings:
    $key_6c51 = { 3b 23 [2] 09 01 [2] 0f 34 [2] 21 34 [2] 1e 28 }

  condition:
    any of them
}