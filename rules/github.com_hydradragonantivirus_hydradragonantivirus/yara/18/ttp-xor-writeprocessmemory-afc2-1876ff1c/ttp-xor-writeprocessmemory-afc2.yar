rule TTP_XOR_WriteProcessMemory_afc2 {
  strings:
    $key_afc2 = { f8 b0 [2] ca 92 [2] cc a7 [2] e2 a7 [2] dd bb }

  condition:
    any of them
}