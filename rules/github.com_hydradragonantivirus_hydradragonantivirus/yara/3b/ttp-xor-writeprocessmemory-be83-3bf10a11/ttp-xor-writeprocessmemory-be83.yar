rule TTP_XOR_WriteProcessMemory_be83 {
  strings:
    $key_be83 = { e9 f1 [2] db d3 [2] dd e6 [2] f3 e6 [2] cc fa }

  condition:
    any of them
}