rule TTP_XOR_WriteProcessMemory_729c {
  strings:
    $key_729c = { 25 ee [2] 17 cc [2] 11 f9 [2] 3f f9 [2] 00 e5 }

  condition:
    any of them
}