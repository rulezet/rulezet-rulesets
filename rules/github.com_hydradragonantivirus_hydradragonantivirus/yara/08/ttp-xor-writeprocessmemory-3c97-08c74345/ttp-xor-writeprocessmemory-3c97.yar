rule TTP_XOR_WriteProcessMemory_3c97 {
  strings:
    $key_3c97 = { 6b e5 [2] 59 c7 [2] 5f f2 [2] 71 f2 [2] 4e ee }

  condition:
    any of them
}