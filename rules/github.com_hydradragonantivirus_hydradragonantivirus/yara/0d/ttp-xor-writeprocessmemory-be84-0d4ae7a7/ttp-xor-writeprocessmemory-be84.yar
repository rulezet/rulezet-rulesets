rule TTP_XOR_WriteProcessMemory_be84 {
  strings:
    $key_be84 = { e9 f6 [2] db d4 [2] dd e1 [2] f3 e1 [2] cc fd }

  condition:
    any of them
}