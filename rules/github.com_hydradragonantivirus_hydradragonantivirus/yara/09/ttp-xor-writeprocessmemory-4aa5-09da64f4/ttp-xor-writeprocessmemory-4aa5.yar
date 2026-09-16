rule TTP_XOR_WriteProcessMemory_4aa5 {
  strings:
    $key_4aa5 = { 1d d7 [2] 2f f5 [2] 29 c0 [2] 07 c0 [2] 38 dc }

  condition:
    any of them
}