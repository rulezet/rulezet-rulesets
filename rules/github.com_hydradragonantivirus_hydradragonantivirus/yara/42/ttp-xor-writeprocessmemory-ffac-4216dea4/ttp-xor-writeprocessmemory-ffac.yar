rule TTP_XOR_WriteProcessMemory_ffac {
  strings:
    $key_ffac = { a8 de [2] 9a fc [2] 9c c9 [2] b2 c9 [2] 8d d5 }

  condition:
    any of them
}