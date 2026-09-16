rule TTP_XOR_WriteProcessMemory_7c58 {
  strings:
    $key_7c58 = { 2b 2a [2] 19 08 [2] 1f 3d [2] 31 3d [2] 0e 21 }

  condition:
    any of them
}