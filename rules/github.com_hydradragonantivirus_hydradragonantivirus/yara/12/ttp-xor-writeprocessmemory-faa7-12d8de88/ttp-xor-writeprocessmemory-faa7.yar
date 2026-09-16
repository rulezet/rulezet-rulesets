rule TTP_XOR_WriteProcessMemory_faa7 {
  strings:
    $key_faa7 = { ad d5 [2] 9f f7 [2] 99 c2 [2] b7 c2 [2] 88 de }

  condition:
    any of them
}