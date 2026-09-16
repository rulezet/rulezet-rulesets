rule TTP_XOR_WriteProcessMemory_48ac {
  strings:
    $key_48ac = { 1f de [2] 2d fc [2] 2b c9 [2] 05 c9 [2] 3a d5 }

  condition:
    any of them
}