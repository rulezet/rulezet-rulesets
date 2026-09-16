rule TTP_XOR_WriteProcessMemory_8dd3 {
  strings:
    $key_8dd3 = { da a1 [2] e8 83 [2] ee b6 [2] c0 b6 [2] ff aa }

  condition:
    any of them
}