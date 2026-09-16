rule TTP_XOR_WriteProcessMemory_3714 {
  strings:
    $key_3714 = { 60 66 [2] 52 44 [2] 54 71 [2] 7a 71 [2] 45 6d }

  condition:
    any of them
}