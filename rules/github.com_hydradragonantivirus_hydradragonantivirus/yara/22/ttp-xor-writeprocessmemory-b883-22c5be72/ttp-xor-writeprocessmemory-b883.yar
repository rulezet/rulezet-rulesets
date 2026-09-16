rule TTP_XOR_WriteProcessMemory_b883 {
  strings:
    $key_b883 = { ef f1 [2] dd d3 [2] db e6 [2] f5 e6 [2] ca fa }

  condition:
    any of them
}