rule TTP_XOR_WriteProcessMemory_edd4 {
  strings:
    $key_edd4 = { ba a6 [2] 88 84 [2] 8e b1 [2] a0 b1 [2] 9f ad }

  condition:
    any of them
}