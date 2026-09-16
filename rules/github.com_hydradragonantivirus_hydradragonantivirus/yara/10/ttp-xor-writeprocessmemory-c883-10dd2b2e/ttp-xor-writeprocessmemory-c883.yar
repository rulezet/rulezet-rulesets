rule TTP_XOR_WriteProcessMemory_c883 {
  strings:
    $key_c883 = { 9f f1 [2] ad d3 [2] ab e6 [2] 85 e6 [2] ba fa }

  condition:
    any of them
}