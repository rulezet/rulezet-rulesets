rule TTP_XOR_WriteProcessMemory_8dd1 {
  strings:
    $key_8dd1 = { da a3 [2] e8 81 [2] ee b4 [2] c0 b4 [2] ff a8 }

  condition:
    any of them
}