rule TTP_XOR_WriteProcessMemory_0723 {
  strings:
    $key_0723 = { 50 51 [2] 62 73 [2] 64 46 [2] 4a 46 [2] 75 5a }

  condition:
    any of them
}