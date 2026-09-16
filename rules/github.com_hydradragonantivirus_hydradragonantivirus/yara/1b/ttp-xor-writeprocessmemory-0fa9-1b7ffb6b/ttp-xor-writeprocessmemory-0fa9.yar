rule TTP_XOR_WriteProcessMemory_0fa9 {
  strings:
    $key_0fa9 = { 58 db [2] 6a f9 [2] 6c cc [2] 42 cc [2] 7d d0 }

  condition:
    any of them
}