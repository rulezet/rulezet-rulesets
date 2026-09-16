rule TTP_XOR_WriteProcessMemory_e738 {
  strings:
    $key_e738 = { b0 4a [2] 82 68 [2] 84 5d [2] aa 5d [2] 95 41 }

  condition:
    any of them
}