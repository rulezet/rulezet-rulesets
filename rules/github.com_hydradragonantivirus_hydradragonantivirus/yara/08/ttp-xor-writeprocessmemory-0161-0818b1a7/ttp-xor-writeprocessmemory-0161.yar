rule TTP_XOR_WriteProcessMemory_0161 {
  strings:
    $key_0161 = { 56 13 [2] 64 31 [2] 62 04 [2] 4c 04 [2] 73 18 }

  condition:
    any of them
}