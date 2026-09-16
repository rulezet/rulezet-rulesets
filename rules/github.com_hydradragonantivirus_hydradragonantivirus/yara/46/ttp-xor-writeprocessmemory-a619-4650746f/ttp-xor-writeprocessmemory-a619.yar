rule TTP_XOR_WriteProcessMemory_a619 {
  strings:
    $key_a619 = { f1 6b [2] c3 49 [2] c5 7c [2] eb 7c [2] d4 60 }

  condition:
    any of them
}