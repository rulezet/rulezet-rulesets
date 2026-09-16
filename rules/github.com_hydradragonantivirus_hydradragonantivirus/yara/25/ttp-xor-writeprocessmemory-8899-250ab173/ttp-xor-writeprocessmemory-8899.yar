rule TTP_XOR_WriteProcessMemory_8899 {
  strings:
    $key_8899 = { df eb [2] ed c9 [2] eb fc [2] c5 fc [2] fa e0 }

  condition:
    any of them
}