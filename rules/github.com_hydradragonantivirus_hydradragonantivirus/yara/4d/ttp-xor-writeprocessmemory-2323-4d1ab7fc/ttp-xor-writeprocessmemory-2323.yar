rule TTP_XOR_WriteProcessMemory_2323 {
  strings:
    $key_2323 = { 74 51 [2] 46 73 [2] 40 46 [2] 6e 46 [2] 51 5a }

  condition:
    any of them
}