rule TTP_XOR_WriteProcessMemory_fc97 {
  strings:
    $key_fc97 = { ab e5 [2] 99 c7 [2] 9f f2 [2] b1 f2 [2] 8e ee }

  condition:
    any of them
}