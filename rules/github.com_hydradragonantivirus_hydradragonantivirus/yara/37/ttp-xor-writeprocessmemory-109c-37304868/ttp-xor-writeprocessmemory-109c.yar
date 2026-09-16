rule TTP_XOR_WriteProcessMemory_109c {
  strings:
    $key_109c = { 47 ee [2] 75 cc [2] 73 f9 [2] 5d f9 [2] 62 e5 }

  condition:
    any of them
}