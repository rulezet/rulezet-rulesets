rule TTP_XOR_WriteProcessMemory_1c97 {
  strings:
    $key_1c97 = { 4b e5 [2] 79 c7 [2] 7f f2 [2] 51 f2 [2] 6e ee }

  condition:
    any of them
}