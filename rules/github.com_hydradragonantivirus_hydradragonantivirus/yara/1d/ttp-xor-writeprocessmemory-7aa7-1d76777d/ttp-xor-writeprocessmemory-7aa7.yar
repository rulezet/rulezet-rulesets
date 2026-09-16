rule TTP_XOR_WriteProcessMemory_7aa7 {
  strings:
    $key_7aa7 = { 2d d5 [2] 1f f7 [2] 19 c2 [2] 37 c2 [2] 08 de }

  condition:
    any of them
}