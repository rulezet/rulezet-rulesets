rule TTP_XOR_WriteProcessMemory_afc7 {
  strings:
    $key_afc7 = { f8 b5 [2] ca 97 [2] cc a2 [2] e2 a2 [2] dd be }

  condition:
    any of them
}