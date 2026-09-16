rule TTP_XOR_WriteProcessMemory_0324 {
  strings:
    $key_0324 = { 54 56 [2] 66 74 [2] 60 41 [2] 4e 41 [2] 71 5d }

  condition:
    any of them
}