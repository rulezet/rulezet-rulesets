rule TTP_XOR_WriteProcessMemory_1aa5 {
  strings:
    $key_1aa5 = { 4d d7 [2] 7f f5 [2] 79 c0 [2] 57 c0 [2] 68 dc }

  condition:
    any of them
}