rule TTP_XOR_WriteProcessMemory_a028 {
  strings:
    $key_a028 = { f7 5a [2] c5 78 [2] c3 4d [2] ed 4d [2] d2 51 }

  condition:
    any of them
}