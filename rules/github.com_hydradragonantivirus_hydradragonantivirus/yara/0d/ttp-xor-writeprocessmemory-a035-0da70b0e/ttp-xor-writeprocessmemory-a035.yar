rule TTP_XOR_WriteProcessMemory_a035 {
  strings:
    $key_a035 = { f7 47 [2] c5 65 [2] c3 50 [2] ed 50 [2] d2 4c }

  condition:
    any of them
}