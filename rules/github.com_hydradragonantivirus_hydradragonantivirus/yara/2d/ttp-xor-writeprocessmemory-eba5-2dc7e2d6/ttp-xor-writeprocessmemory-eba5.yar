rule TTP_XOR_WriteProcessMemory_eba5 {
  strings:
    $key_eba5 = { bc d7 [2] 8e f5 [2] 88 c0 [2] a6 c0 [2] 99 dc }

  condition:
    any of them
}