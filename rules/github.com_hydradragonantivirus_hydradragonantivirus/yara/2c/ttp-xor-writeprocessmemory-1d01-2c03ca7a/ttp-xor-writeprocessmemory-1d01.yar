rule TTP_XOR_WriteProcessMemory_1d01 {
  strings:
    $key_1d01 = { 4a 73 [2] 78 51 [2] 7e 64 [2] 50 64 [2] 6f 78 }

  condition:
    any of them
}