rule TTP_XOR_WriteProcessMemory_7f01 {
  strings:
    $key_7f01 = { 28 73 [2] 1a 51 [2] 1c 64 [2] 32 64 [2] 0d 78 }

  condition:
    any of them
}