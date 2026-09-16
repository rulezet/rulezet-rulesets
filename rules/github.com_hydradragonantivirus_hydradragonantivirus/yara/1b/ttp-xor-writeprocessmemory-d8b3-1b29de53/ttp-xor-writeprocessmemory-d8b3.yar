rule TTP_XOR_WriteProcessMemory_d8b3 {
  strings:
    $key_d8b3 = { 8f c1 [2] bd e3 [2] bb d6 [2] 95 d6 [2] aa ca }

  condition:
    any of them
}