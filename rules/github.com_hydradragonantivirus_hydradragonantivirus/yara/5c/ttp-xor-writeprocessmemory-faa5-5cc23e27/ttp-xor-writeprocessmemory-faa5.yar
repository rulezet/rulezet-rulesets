rule TTP_XOR_WriteProcessMemory_faa5 {
  strings:
    $key_faa5 = { ad d7 [2] 9f f5 [2] 99 c0 [2] b7 c0 [2] 88 dc }

  condition:
    any of them
}