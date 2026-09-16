rule TTP_XOR_WriteProcessMemory_e65d {
  strings:
    $key_e65d = { b1 2f [2] 83 0d [2] 85 38 [2] ab 38 [2] 94 24 }

  condition:
    any of them
}