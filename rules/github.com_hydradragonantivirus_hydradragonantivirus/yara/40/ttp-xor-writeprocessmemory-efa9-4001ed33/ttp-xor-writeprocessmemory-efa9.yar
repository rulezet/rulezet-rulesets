rule TTP_XOR_WriteProcessMemory_efa9 {
  strings:
    $key_efa9 = { b8 db [2] 8a f9 [2] 8c cc [2] a2 cc [2] 9d d0 }

  condition:
    any of them
}