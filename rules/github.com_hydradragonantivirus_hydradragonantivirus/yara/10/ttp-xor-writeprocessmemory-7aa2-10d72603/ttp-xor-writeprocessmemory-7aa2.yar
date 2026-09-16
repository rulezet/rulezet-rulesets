rule TTP_XOR_WriteProcessMemory_7aa2 {
  strings:
    $key_7aa2 = { 2d d0 [2] 1f f2 [2] 19 c7 [2] 37 c7 [2] 08 db }

  condition:
    any of them
}