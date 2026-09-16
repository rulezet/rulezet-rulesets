rule TTP_XOR_WriteProcessMemory_be92 {
  strings:
    $key_be92 = { e9 e0 [2] db c2 [2] dd f7 [2] f3 f7 [2] cc eb }

  condition:
    any of them
}