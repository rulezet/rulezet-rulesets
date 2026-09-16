rule TTP_XOR_WriteProcessMemory_2c97 {
  strings:
    $key_2c97 = { 7b e5 [2] 49 c7 [2] 4f f2 [2] 61 f2 [2] 5e ee }

  condition:
    any of them
}