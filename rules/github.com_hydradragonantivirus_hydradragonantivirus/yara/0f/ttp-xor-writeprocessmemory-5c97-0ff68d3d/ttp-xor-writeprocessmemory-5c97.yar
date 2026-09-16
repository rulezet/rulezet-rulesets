rule TTP_XOR_WriteProcessMemory_5c97 {
  strings:
    $key_5c97 = { 0b e5 [2] 39 c7 [2] 3f f2 [2] 11 f2 [2] 2e ee }

  condition:
    any of them
}