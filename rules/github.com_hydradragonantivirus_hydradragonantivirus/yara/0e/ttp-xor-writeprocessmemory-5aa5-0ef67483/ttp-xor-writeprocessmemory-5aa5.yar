rule TTP_XOR_WriteProcessMemory_5aa5 {
  strings:
    $key_5aa5 = { 0d d7 [2] 3f f5 [2] 39 c0 [2] 17 c0 [2] 28 dc }

  condition:
    any of them
}