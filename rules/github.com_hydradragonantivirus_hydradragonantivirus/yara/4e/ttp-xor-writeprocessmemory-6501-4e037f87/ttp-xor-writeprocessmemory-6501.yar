rule TTP_XOR_WriteProcessMemory_6501 {
  strings:
    $key_6501 = { 32 73 [2] 00 51 [2] 06 64 [2] 28 64 [2] 17 78 }

  condition:
    any of them
}