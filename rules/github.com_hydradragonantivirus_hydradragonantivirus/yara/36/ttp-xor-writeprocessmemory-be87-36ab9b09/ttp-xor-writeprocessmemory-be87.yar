rule TTP_XOR_WriteProcessMemory_be87 {
  strings:
    $key_be87 = { e9 f5 [2] db d7 [2] dd e2 [2] f3 e2 [2] cc fe }

  condition:
    any of them
}