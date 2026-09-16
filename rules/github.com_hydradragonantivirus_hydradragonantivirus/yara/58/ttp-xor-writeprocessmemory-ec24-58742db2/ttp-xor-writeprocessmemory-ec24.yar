rule TTP_XOR_WriteProcessMemory_ec24 {
  strings:
    $key_ec24 = { bb 56 [2] 89 74 [2] 8f 41 [2] a1 41 [2] 9e 5d }

  condition:
    any of them
}