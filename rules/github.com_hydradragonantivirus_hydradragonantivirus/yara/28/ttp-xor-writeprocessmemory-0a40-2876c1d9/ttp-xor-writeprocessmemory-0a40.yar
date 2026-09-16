rule TTP_XOR_WriteProcessMemory_0a40 {
  strings:
    $key_0a40 = { 5d 32 [2] 6f 10 [2] 69 25 [2] 47 25 [2] 78 39 }

  condition:
    any of them
}