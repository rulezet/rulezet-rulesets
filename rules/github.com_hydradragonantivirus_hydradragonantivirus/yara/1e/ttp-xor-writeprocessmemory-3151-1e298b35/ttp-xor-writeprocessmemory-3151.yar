rule TTP_XOR_WriteProcessMemory_3151 {
  strings:
    $key_3151 = { 66 23 [2] 54 01 [2] 52 34 [2] 7c 34 [2] 43 28 }

  condition:
    any of them
}