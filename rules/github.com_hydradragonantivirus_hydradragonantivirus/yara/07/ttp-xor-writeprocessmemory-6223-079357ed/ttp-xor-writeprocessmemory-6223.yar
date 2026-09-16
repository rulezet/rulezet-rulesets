rule TTP_XOR_WriteProcessMemory_6223 {
  strings:
    $key_6223 = { 35 51 [2] 07 73 [2] 01 46 [2] 2f 46 [2] 10 5a }

  condition:
    any of them
}