rule TTP_XOR_WriteProcessMemory_e758 {
  strings:
    $key_e758 = { b0 2a [2] 82 08 [2] 84 3d [2] aa 3d [2] 95 21 }

  condition:
    any of them
}