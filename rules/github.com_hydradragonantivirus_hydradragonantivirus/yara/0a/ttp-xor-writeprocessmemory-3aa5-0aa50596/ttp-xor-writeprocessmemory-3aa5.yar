rule TTP_XOR_WriteProcessMemory_3aa5 {
  strings:
    $key_3aa5 = { 6d d7 [2] 5f f5 [2] 59 c0 [2] 77 c0 [2] 48 dc }

  condition:
    any of them
}