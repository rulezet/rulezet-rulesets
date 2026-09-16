rule TTP_XOR_WriteProcessMemory_faa1 {
  strings:
    $key_faa1 = { ad d3 [2] 9f f1 [2] 99 c4 [2] b7 c4 [2] 88 d8 }

  condition:
    any of them
}