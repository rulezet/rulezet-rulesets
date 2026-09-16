rule TTP_XOR_WriteProcessMemory_ec34 {
  strings:
    $key_ec34 = { bb 46 [2] 89 64 [2] 8f 51 [2] a1 51 [2] 9e 4d }

  condition:
    any of them
}