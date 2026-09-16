rule TTP_XOR_WriteProcessMemory_70b3 {
  strings:
    $key_70b3 = { 27 c1 [2] 15 e3 [2] 13 d6 [2] 3d d6 [2] 02 ca }

  condition:
    any of them
}