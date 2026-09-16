rule TTP_XOR_WriteProcessMemory_239c {
  strings:
    $key_239c = { 74 ee [2] 46 cc [2] 40 f9 [2] 6e f9 [2] 51 e5 }

  condition:
    any of them
}