rule TTP_XOR_WriteProcessMemory_e958 {
  strings:
    $key_e958 = { be 2a [2] 8c 08 [2] 8a 3d [2] a4 3d [2] 9b 21 }

  condition:
    any of them
}