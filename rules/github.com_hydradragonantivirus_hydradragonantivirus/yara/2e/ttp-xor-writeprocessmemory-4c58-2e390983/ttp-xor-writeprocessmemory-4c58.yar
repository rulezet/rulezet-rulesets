rule TTP_XOR_WriteProcessMemory_4c58 {
  strings:
    $key_4c58 = { 1b 2a [2] 29 08 [2] 2f 3d [2] 01 3d [2] 3e 21 }

  condition:
    any of them
}