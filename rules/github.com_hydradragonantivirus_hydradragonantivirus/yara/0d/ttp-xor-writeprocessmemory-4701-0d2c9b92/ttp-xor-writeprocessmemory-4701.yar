rule TTP_XOR_WriteProcessMemory_4701 {
  strings:
    $key_4701 = { 10 73 [2] 22 51 [2] 24 64 [2] 0a 64 [2] 35 78 }

  condition:
    any of them
}