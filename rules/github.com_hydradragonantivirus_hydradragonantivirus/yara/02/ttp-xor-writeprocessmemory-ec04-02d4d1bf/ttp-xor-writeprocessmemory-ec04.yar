rule TTP_XOR_WriteProcessMemory_ec04 {
  strings:
    $key_ec04 = { bb 76 [2] 89 54 [2] 8f 61 [2] a1 61 [2] 9e 7d }

  condition:
    any of them
}