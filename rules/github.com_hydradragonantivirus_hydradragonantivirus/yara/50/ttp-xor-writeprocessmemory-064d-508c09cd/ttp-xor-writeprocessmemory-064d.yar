rule TTP_XOR_WriteProcessMemory_064d {
  strings:
    $key_064d = { 51 3f [2] 63 1d [2] 65 28 [2] 4b 28 [2] 74 34 }

  condition:
    any of them
}