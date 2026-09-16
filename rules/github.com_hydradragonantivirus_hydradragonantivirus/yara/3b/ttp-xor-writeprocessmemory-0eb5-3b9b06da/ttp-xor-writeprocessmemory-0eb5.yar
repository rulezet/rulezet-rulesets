rule TTP_XOR_WriteProcessMemory_0eb5 {
  strings:
    $key_0eb5 = { 59 c7 [2] 6b e5 [2] 6d d0 [2] 43 d0 [2] 7c cc }

  condition:
    any of them
}