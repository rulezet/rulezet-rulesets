rule TTP_XOR_WriteProcessMemory_ec23 {
  strings:
    $key_ec23 = { bb 51 [2] 89 73 [2] 8f 46 [2] a1 46 [2] 9e 5a }

  condition:
    any of them
}