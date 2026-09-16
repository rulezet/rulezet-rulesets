rule TTP_XOR_WriteProcessMemory_2334 {
  strings:
    $key_2334 = { 74 46 [2] 46 64 [2] 40 51 [2] 6e 51 [2] 51 4d }

  condition:
    any of them
}