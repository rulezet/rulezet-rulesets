rule TTP_XOR_WriteProcessMemory_76a9 {
  strings:
    $key_76a9 = { 21 db [2] 13 f9 [2] 15 cc [2] 3b cc [2] 04 d0 }

  condition:
    any of them
}