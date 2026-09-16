rule TTP_XOR_WriteProcessMemory_fc94 {
  strings:
    $key_fc94 = { ab e6 [2] 99 c4 [2] 9f f1 [2] b1 f1 [2] 8e ed }

  condition:
    any of them
}