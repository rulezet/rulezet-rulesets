rule TTP_XOR_WriteProcessMemory_ec38 {
  strings:
    $key_ec38 = { bb 4a [2] 89 68 [2] 8f 5d [2] a1 5d [2] 9e 41 }

  condition:
    any of them
}