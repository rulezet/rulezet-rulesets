rule TTP_XOR_WriteProcessMemory_1afb {
  strings:
    $key_1afb = { 4d 89 [2] 7f ab [2] 79 9e [2] 57 9e [2] 68 82 }

  condition:
    any of them
}