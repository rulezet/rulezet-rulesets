rule TTP_XOR_WriteProcessMemory_a609 {
  strings:
    $key_a609 = { f1 7b [2] c3 59 [2] c5 6c [2] eb 6c [2] d4 70 }

  condition:
    any of them
}