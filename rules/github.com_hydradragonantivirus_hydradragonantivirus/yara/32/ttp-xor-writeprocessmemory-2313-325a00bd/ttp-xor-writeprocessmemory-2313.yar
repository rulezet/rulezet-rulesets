rule TTP_XOR_WriteProcessMemory_2313 {
  strings:
    $key_2313 = { 74 61 [2] 46 43 [2] 40 76 [2] 6e 76 [2] 51 6a }

  condition:
    any of them
}