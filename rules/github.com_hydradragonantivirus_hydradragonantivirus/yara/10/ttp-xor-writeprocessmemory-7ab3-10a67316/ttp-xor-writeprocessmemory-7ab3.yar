rule TTP_XOR_WriteProcessMemory_7ab3 {
  strings:
    $key_7ab3 = { 2d c1 [2] 1f e3 [2] 19 d6 [2] 37 d6 [2] 08 ca }

  condition:
    any of them
}