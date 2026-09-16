rule TTP_XOR_WriteProcessMemory_3eb5 {
  strings:
    $key_3eb5 = { 69 c7 [2] 5b e5 [2] 5d d0 [2] 73 d0 [2] 4c cc }

  condition:
    any of them
}