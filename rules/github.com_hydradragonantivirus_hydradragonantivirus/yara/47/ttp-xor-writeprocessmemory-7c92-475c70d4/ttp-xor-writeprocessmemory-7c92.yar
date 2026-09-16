rule TTP_XOR_WriteProcessMemory_7c92 {
  strings:
    $key_7c92 = { 2b e0 [2] 19 c2 [2] 1f f7 [2] 31 f7 [2] 0e eb }

  condition:
    any of them
}