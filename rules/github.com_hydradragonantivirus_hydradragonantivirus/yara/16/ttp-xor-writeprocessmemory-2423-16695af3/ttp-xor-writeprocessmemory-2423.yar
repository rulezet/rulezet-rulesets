rule TTP_XOR_WriteProcessMemory_2423 {
  strings:
    $key_2423 = { 73 51 [2] 41 73 [2] 47 46 [2] 69 46 [2] 56 5a }

  condition:
    any of them
}