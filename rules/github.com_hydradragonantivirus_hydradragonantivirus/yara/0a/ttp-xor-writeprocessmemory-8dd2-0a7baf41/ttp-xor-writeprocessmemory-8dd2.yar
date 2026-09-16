rule TTP_XOR_WriteProcessMemory_8dd2 {
  strings:
    $key_8dd2 = { da a0 [2] e8 82 [2] ee b7 [2] c0 b7 [2] ff ab }

  condition:
    any of them
}