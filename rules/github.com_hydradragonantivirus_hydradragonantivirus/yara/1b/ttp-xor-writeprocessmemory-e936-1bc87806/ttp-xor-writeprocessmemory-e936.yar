rule TTP_XOR_WriteProcessMemory_e936 {
  strings:
    $key_e936 = { be 44 [2] 8c 66 [2] 8a 53 [2] a4 53 [2] 9b 4f }

  condition:
    any of them
}