rule TTP_XOR_WriteProcessMemory_03a9 {
  strings:
    $key_03a9 = { 54 db [2] 66 f9 [2] 60 cc [2] 4e cc [2] 71 d0 }

  condition:
    any of them
}