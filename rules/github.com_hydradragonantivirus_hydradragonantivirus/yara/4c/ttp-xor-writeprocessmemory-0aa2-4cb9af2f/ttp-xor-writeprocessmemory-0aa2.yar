rule TTP_XOR_WriteProcessMemory_0aa2 {
  strings:
    $key_0aa2 = { 5d d0 [2] 6f f2 [2] 69 c7 [2] 47 c7 [2] 78 db }

  condition:
    any of them
}