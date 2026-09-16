rule TTP_XOR_WriteProcessMemory_be80 {
  strings:
    $key_be80 = { e9 f2 [2] db d0 [2] dd e5 [2] f3 e5 [2] cc f9 }

  condition:
    any of them
}