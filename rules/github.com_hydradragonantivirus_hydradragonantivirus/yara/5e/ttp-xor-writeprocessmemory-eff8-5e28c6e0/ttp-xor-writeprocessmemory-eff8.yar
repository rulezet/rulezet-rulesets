rule TTP_XOR_WriteProcessMemory_eff8 {
  strings:
    $key_eff8 = { b8 8a [2] 8a a8 [2] 8c 9d [2] a2 9d [2] 9d 81 }

  condition:
    any of them
}