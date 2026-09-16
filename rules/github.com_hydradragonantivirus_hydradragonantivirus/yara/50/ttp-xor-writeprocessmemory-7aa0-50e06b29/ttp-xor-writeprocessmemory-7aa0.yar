rule TTP_XOR_WriteProcessMemory_7aa0 {
  strings:
    $key_7aa0 = { 2d d2 [2] 1f f0 [2] 19 c5 [2] 37 c5 [2] 08 d9 }

  condition:
    any of them
}