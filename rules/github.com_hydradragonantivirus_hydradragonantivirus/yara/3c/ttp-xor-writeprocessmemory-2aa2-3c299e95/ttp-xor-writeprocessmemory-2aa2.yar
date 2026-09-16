rule TTP_XOR_WriteProcessMemory_2aa2 {
  strings:
    $key_2aa2 = { 7d d0 [2] 4f f2 [2] 49 c7 [2] 67 c7 [2] 58 db }

  condition:
    any of them
}