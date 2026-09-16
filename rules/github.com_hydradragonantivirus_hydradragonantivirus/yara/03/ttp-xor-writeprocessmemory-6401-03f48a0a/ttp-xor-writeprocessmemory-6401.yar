rule TTP_XOR_WriteProcessMemory_6401 {
  strings:
    $key_6401 = { 33 73 [2] 01 51 [2] 07 64 [2] 29 64 [2] 16 78 }

  condition:
    any of them
}