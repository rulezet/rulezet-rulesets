rule TTP_XOR_WriteProcessMemory_ec74 {
  strings:
    $key_ec74 = { bb 06 [2] 89 24 [2] 8f 11 [2] a1 11 [2] 9e 0d }

  condition:
    any of them
}