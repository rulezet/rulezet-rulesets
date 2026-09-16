rule TTP_XOR_WriteProcessMemory_e892 {
  strings:
    $key_e892 = { bf e0 [2] 8d c2 [2] 8b f7 [2] a5 f7 [2] 9a eb }

  condition:
    any of them
}