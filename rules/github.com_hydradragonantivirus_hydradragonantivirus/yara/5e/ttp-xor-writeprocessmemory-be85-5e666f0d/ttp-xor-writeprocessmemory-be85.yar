rule TTP_XOR_WriteProcessMemory_be85 {
  strings:
    $key_be85 = { e9 f7 [2] db d5 [2] dd e0 [2] f3 e0 [2] cc fc }

  condition:
    any of them
}