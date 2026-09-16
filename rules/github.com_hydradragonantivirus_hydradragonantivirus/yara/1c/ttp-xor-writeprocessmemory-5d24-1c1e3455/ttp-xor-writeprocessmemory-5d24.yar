rule TTP_XOR_WriteProcessMemory_5d24 {
  strings:
    $key_5d24 = { 0a 56 [2] 38 74 [2] 3e 41 [2] 10 41 [2] 2f 5d }

  condition:
    any of them
}