rule TTP_XOR_WriteProcessMemory_ec71 {
  strings:
    $key_ec71 = { bb 03 [2] 89 21 [2] 8f 14 [2] a1 14 [2] 9e 08 }

  condition:
    any of them
}