rule TTP_XOR_WriteProcessMemory_1b13 {
  strings:
    $key_1b13 = { 4c 61 [2] 7e 43 [2] 78 76 [2] 56 76 [2] 69 6a }

  condition:
    any of them
}