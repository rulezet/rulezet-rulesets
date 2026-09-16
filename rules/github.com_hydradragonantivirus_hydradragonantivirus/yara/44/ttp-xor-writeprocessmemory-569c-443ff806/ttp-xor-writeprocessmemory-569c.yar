rule TTP_XOR_WriteProcessMemory_569c {
  strings:
    $key_569c = { 01 ee [2] 33 cc [2] 35 f9 [2] 1b f9 [2] 24 e5 }

  condition:
    any of them
}