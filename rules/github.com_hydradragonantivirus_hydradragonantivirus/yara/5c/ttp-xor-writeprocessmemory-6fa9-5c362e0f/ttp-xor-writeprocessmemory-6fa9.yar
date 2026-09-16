rule TTP_XOR_WriteProcessMemory_6fa9 {
  strings:
    $key_6fa9 = { 38 db [2] 0a f9 [2] 0c cc [2] 22 cc [2] 1d d0 }

  condition:
    any of them
}