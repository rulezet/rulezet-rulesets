rule TTP_XOR_WriteProcessMemory_afd3 {
  strings:
    $key_afd3 = { f8 a1 [2] ca 83 [2] cc b6 [2] e2 b6 [2] dd aa }

  condition:
    any of them
}