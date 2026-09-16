rule TTP_XOR_WriteProcessMemory_fc93 {
  strings:
    $key_fc93 = { ab e1 [2] 99 c3 [2] 9f f6 [2] b1 f6 [2] 8e ea }

  condition:
    any of them
}