rule TTP_XOR_WriteProcessMemory_2367 {
  strings:
    $key_2367 = { 74 15 [2] 46 37 [2] 40 02 [2] 6e 02 [2] 51 1e }

  condition:
    any of them
}