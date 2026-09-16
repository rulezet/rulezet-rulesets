rule TTP_XOR_WriteProcessMemory_aab3 {
  strings:
    $key_aab3 = { fd c1 [2] cf e3 [2] c9 d6 [2] e7 d6 [2] d8 ca }

  condition:
    any of them
}