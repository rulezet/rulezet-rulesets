rule TTP_XOR_WriteProcessMemory_3114 {
  strings:
    $key_3114 = { 66 66 [2] 54 44 [2] 52 71 [2] 7c 71 [2] 43 6d }

  condition:
    any of them
}