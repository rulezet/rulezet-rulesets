rule TTP_XOR_WriteProcessMemory_0ab3 {
  strings:
    $key_0ab3 = { 5d c1 [2] 6f e3 [2] 69 d6 [2] 47 d6 [2] 78 ca }

  condition:
    any of them
}