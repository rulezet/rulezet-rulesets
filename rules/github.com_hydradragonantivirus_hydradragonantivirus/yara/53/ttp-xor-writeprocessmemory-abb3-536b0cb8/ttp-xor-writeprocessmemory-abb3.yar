rule TTP_XOR_WriteProcessMemory_abb3 {
  strings:
    $key_abb3 = { fc c1 [2] ce e3 [2] c8 d6 [2] e6 d6 [2] d9 ca }

  condition:
    any of them
}