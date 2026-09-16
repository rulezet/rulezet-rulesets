rule TTP_XOR_WriteProcessMemory_edd7 {
  strings:
    $key_edd7 = { ba a5 [2] 88 87 [2] 8e b2 [2] a0 b2 [2] 9f ae }

  condition:
    any of them
}