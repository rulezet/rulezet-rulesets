rule TTP_XOR_WriteProcessMemory_ec4d {
  strings:
    $key_ec4d = { bb 3f [2] 89 1d [2] 8f 28 [2] a1 28 [2] 9e 34 }

  condition:
    any of them
}