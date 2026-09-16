rule TTP_XOR_WriteProcessMemory_aab5 {
  strings:
    $key_aab5 = { fd c7 [2] cf e5 [2] c9 d0 [2] e7 d0 [2] d8 cc }

  condition:
    any of them
}