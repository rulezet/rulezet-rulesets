rule TTP_XOR_WriteProcessMemory_7f61 {
  strings:
    $key_7f61 = { 28 13 [2] 1a 31 [2] 1c 04 [2] 32 04 [2] 0d 18 }

  condition:
    any of them
}