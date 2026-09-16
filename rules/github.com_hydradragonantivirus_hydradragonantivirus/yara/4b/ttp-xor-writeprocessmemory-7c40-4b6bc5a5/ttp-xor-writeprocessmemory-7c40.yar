rule TTP_XOR_WriteProcessMemory_7c40 {
  strings:
    $key_7c40 = { 2b 32 [2] 19 10 [2] 1f 25 [2] 31 25 [2] 0e 39 }

  condition:
    any of them
}