rule TTP_XOR_WriteProcessMemory_0aa5 {
  strings:
    $key_0aa5 = { 5d d7 [2] 6f f5 [2] 69 c0 [2] 47 c0 [2] 78 dc }

  condition:
    any of them
}