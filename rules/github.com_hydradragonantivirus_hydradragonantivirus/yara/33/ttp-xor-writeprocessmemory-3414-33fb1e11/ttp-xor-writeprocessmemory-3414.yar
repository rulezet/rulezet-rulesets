rule TTP_XOR_WriteProcessMemory_3414 {
  strings:
    $key_3414 = { 63 66 [2] 51 44 [2] 57 71 [2] 79 71 [2] 46 6d }

  condition:
    any of them
}