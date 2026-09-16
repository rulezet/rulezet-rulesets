rule TTP_XOR_WriteProcessMemory_259c {
  strings:
    $key_259c = { 72 ee [2] 40 cc [2] 46 f9 [2] 68 f9 [2] 57 e5 }

  condition:
    any of them
}