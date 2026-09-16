rule TTP_XOR_WriteProcessMemory_e903 {
  strings:
    $key_e903 = { be 71 [2] 8c 53 [2] 8a 66 [2] a4 66 [2] 9b 7a }

  condition:
    any of them
}