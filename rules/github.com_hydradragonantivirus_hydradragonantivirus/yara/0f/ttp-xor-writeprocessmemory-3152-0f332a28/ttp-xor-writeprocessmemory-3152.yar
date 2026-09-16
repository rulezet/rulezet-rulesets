rule TTP_XOR_WriteProcessMemory_3152 {
  strings:
    $key_3152 = { 66 20 [2] 54 02 [2] 52 37 [2] 7c 37 [2] 43 2b }

  condition:
    any of them
}