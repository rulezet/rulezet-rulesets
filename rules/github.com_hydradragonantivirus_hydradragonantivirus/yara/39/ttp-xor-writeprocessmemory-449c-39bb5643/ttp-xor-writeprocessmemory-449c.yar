rule TTP_XOR_WriteProcessMemory_449c {
  strings:
    $key_449c = { 13 ee [2] 21 cc [2] 27 f9 [2] 09 f9 [2] 36 e5 }

  condition:
    any of them
}