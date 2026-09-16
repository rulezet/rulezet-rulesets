rule TTP_XOR_WriteProcessMemory_5aa2 {
  strings:
    $key_5aa2 = { 0d d0 [2] 3f f2 [2] 39 c7 [2] 17 c7 [2] 28 db }

  condition:
    any of them
}