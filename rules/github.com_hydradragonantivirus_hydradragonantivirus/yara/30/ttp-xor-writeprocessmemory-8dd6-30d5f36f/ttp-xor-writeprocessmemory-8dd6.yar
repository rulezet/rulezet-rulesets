rule TTP_XOR_WriteProcessMemory_8dd6 {
  strings:
    $key_8dd6 = { da a4 [2] e8 86 [2] ee b3 [2] c0 b3 [2] ff af }

  condition:
    any of them
}