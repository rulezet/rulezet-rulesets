rule TTP_XOR_WriteProcessMemory_4d01 {
  strings:
    $key_4d01 = { 1a 73 [2] 28 51 [2] 2e 64 [2] 00 64 [2] 3f 78 }

  condition:
    any of them
}