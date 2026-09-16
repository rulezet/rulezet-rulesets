rule TTP_XOR_WriteProcessMemory_ec6d {
  strings:
    $key_ec6d = { bb 1f [2] 89 3d [2] 8f 08 [2] a1 08 [2] 9e 14 }

  condition:
    any of them
}