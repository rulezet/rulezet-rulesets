rule TTP_XOR_WriteProcessMemory_55b3 {
  strings:
    $key_55b3 = { 02 c1 [2] 30 e3 [2] 36 d6 [2] 18 d6 [2] 27 ca }

  condition:
    any of them
}