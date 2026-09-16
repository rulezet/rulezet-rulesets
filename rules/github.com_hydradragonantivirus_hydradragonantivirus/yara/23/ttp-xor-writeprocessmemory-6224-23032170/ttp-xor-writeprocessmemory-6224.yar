rule TTP_XOR_WriteProcessMemory_6224 {
  strings:
    $key_6224 = { 35 56 [2] 07 74 [2] 01 41 [2] 2f 41 [2] 10 5d }

  condition:
    any of them
}