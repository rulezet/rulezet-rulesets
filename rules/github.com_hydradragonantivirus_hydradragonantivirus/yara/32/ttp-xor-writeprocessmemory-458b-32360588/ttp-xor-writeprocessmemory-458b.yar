rule TTP_XOR_WriteProcessMemory_458b {
  strings:
    $key_458b = { 12 f9 [2] 20 db [2] 26 ee [2] 08 ee [2] 37 f2 }

  condition:
    any of them
}