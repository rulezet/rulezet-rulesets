rule TTP_XOR_WriteProcessMemory_ec17 {
  strings:
    $key_ec17 = { bb 65 [2] 89 47 [2] 8f 72 [2] a1 72 [2] 9e 6e }

  condition:
    any of them
}