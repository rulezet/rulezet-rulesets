rule TTP_XOR_WriteProcessMemory_214d {
  strings:
    $key_214d = { 76 3f [2] 44 1d [2] 42 28 [2] 6c 28 [2] 53 34 }

  condition:
    any of them
}