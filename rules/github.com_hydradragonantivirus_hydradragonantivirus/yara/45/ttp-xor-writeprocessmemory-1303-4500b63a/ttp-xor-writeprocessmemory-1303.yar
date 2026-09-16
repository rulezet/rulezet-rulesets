rule TTP_XOR_WriteProcessMemory_1303 {
  strings:
    $key_1303 = { 44 71 [2] 76 53 [2] 70 66 [2] 5e 66 [2] 61 7a }

  condition:
    any of them
}