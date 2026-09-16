rule TTP_XOR_WriteProcessMemory_94b3 {
  strings:
    $key_94b3 = { c3 c1 [2] f1 e3 [2] f7 d6 [2] d9 d6 [2] e6 ca }

  condition:
    any of them
}