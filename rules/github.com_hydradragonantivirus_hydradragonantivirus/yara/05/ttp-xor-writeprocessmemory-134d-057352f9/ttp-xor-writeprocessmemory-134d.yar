rule TTP_XOR_WriteProcessMemory_134d {
  strings:
    $key_134d = { 44 3f [2] 76 1d [2] 70 28 [2] 5e 28 [2] 61 34 }

  condition:
    any of them
}