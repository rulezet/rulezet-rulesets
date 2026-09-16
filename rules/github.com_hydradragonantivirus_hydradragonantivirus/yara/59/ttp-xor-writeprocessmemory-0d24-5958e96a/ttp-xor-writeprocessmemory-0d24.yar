rule TTP_XOR_WriteProcessMemory_0d24 {
  strings:
    $key_0d24 = { 5a 56 [2] 68 74 [2] 6e 41 [2] 40 41 [2] 7f 5d }

  condition:
    any of them
}