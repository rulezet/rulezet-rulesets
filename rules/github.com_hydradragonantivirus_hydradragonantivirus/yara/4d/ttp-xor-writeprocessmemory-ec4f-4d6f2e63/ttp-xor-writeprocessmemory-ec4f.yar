rule TTP_XOR_WriteProcessMemory_ec4f {
  strings:
    $key_ec4f = { bb 3d [2] 89 1f [2] 8f 2a [2] a1 2a [2] 9e 36 }

  condition:
    any of them
}