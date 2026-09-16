rule TTP_XOR_WriteProcessMemory_ec65 {
  strings:
    $key_ec65 = { bb 17 [2] 89 35 [2] 8f 00 [2] a1 00 [2] 9e 1c }

  condition:
    any of them
}