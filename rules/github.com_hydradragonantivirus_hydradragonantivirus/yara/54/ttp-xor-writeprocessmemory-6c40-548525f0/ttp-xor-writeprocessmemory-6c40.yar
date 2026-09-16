rule TTP_XOR_WriteProcessMemory_6c40 {
  strings:
    $key_6c40 = { 3b 32 [2] 09 10 [2] 0f 25 [2] 21 25 [2] 1e 39 }

  condition:
    any of them
}