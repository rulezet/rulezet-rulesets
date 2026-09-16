rule TTP_XOR_WriteProcessMemory_2d24 {
  strings:
    $key_2d24 = { 7a 56 [2] 48 74 [2] 4e 41 [2] 60 41 [2] 5f 5d }

  condition:
    any of them
}