rule TTP_XOR_WriteProcessMemory_0c40 {
  strings:
    $key_0c40 = { 5b 32 [2] 69 10 [2] 6f 25 [2] 41 25 [2] 7e 39 }

  condition:
    any of them
}