rule TTP_XOR_WriteProcessMemory_6aa5 {
  strings:
    $key_6aa5 = { 3d d7 [2] 0f f5 [2] 09 c0 [2] 27 c0 [2] 18 dc }

  condition:
    any of them
}