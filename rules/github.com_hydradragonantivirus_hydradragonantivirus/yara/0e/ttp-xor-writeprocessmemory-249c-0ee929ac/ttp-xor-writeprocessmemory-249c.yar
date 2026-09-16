rule TTP_XOR_WriteProcessMemory_249c {
  strings:
    $key_249c = { 73 ee [2] 41 cc [2] 47 f9 [2] 69 f9 [2] 56 e5 }

  condition:
    any of them
}