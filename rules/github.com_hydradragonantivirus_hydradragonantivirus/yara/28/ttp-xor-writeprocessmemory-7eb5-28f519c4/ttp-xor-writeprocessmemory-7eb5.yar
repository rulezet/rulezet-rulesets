rule TTP_XOR_WriteProcessMemory_7eb5 {
  strings:
    $key_7eb5 = { 29 c7 [2] 1b e5 [2] 1d d0 [2] 33 d0 [2] 0c cc }

  condition:
    any of them
}