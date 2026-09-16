rule TTP_XOR_WriteProcessMemory_7fa9 {
  strings:
    $key_7fa9 = { 28 db [2] 1a f9 [2] 1c cc [2] 32 cc [2] 0d d0 }

  condition:
    any of them
}