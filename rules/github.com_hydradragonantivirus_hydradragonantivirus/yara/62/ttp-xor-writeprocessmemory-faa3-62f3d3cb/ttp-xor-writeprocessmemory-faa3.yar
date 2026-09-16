rule TTP_XOR_WriteProcessMemory_faa3 {
  strings:
    $key_faa3 = { ad d1 [2] 9f f3 [2] 99 c6 [2] b7 c6 [2] 88 da }

  condition:
    any of them
}