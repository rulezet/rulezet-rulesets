rule TTP_XOR_WriteProcessMemory_4023 {
  strings:
    $key_4023 = { 17 51 [2] 25 73 [2] 23 46 [2] 0d 46 [2] 32 5a }

  condition:
    any of them
}