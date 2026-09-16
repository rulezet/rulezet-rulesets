rule TTP_XOR_WriteProcessMemory_e64d {
  strings:
    $key_e64d = { b1 3f [2] 83 1d [2] 85 28 [2] ab 28 [2] 94 34 }

  condition:
    any of them
}