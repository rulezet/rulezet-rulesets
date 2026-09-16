rule TTP_XOR_WriteProcessMemory_a60c {
  strings:
    $key_a60c = { f1 7e [2] c3 5c [2] c5 69 [2] eb 69 [2] d4 75 }

  condition:
    any of them
}