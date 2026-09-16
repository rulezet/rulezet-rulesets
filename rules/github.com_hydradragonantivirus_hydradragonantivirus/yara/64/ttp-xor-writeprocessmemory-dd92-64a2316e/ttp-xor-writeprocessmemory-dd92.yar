rule TTP_XOR_WriteProcessMemory_dd92 {
  strings:
    $key_dd92 = { 8a e0 [2] b8 c2 [2] be f7 [2] 90 f7 [2] af eb }

  condition:
    any of them
}