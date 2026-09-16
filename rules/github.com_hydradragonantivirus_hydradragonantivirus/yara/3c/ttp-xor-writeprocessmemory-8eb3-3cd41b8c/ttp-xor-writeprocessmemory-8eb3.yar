rule TTP_XOR_WriteProcessMemory_8eb3 {
  strings:
    $key_8eb3 = { d9 c1 [2] eb e3 [2] ed d6 [2] c3 d6 [2] fc ca }

  condition:
    any of them
}