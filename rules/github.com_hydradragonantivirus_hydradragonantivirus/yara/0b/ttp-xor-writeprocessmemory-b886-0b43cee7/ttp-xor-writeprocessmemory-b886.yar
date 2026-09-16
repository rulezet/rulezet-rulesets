rule TTP_XOR_WriteProcessMemory_b886 {
  strings:
    $key_b886 = { ef f4 [2] dd d6 [2] db e3 [2] f5 e3 [2] ca ff }

  condition:
    any of them
}