rule TTP_XOR_WriteProcessMemory_8883 {
  strings:
    $key_8883 = { df f1 [2] ed d3 [2] eb e6 [2] c5 e6 [2] fa fa }

  condition:
    any of them
}