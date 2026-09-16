rule TTP_XOR_WriteProcessMemory_2303 {
  strings:
    $key_2303 = { 74 71 [2] 46 53 [2] 40 66 [2] 6e 66 [2] 51 7a }

  condition:
    any of them
}