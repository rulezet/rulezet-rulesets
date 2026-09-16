rule TTP_XOR_WriteProcessMemory_0701 {
  strings:
    $key_0701 = { 50 73 [2] 62 51 [2] 64 64 [2] 4a 64 [2] 75 78 }

  condition:
    any of them
}