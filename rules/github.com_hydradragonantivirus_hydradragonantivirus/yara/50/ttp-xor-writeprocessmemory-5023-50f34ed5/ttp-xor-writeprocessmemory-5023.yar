rule TTP_XOR_WriteProcessMemory_5023 {
  strings:
    $key_5023 = { 07 51 [2] 35 73 [2] 33 46 [2] 1d 46 [2] 22 5a }

  condition:
    any of them
}