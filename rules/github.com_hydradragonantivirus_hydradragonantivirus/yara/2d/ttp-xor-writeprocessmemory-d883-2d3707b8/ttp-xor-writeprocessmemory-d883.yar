rule TTP_XOR_WriteProcessMemory_d883 {
  strings:
    $key_d883 = { 8f f1 [2] bd d3 [2] bb e6 [2] 95 e6 [2] aa fa }

  condition:
    any of them
}