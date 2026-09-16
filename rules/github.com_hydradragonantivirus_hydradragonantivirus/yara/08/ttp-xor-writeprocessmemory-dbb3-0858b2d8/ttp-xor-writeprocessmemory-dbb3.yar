rule TTP_XOR_WriteProcessMemory_dbb3 {
  strings:
    $key_dbb3 = { 8c c1 [2] be e3 [2] b8 d6 [2] 96 d6 [2] a9 ca }

  condition:
    any of them
}