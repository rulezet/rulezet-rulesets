rule TTP_XOR_WriteProcessMemory_be94 {
  strings:
    $key_be94 = { e9 e6 [2] db c4 [2] dd f1 [2] f3 f1 [2] cc ed }

  condition:
    any of them
}