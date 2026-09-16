rule TTP_XOR_WriteProcessMemory_a638 {
  strings:
    $key_a638 = { f1 4a [2] c3 68 [2] c5 5d [2] eb 5d [2] d4 41 }

  condition:
    any of them
}