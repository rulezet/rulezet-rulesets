rule TTP_XOR_WriteProcessMemory_ecc4 {
  strings:
    $key_ecc4 = { bb b6 [2] 89 94 [2] 8f a1 [2] a1 a1 [2] 9e bd }

  condition:
    any of them
}