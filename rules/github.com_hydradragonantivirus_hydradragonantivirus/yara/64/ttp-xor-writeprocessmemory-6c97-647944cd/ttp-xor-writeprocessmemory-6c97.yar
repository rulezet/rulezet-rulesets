rule TTP_XOR_WriteProcessMemory_6c97 {
  strings:
    $key_6c97 = { 3b e5 [2] 09 c7 [2] 0f f2 [2] 21 f2 [2] 1e ee }

  condition:
    any of them
}