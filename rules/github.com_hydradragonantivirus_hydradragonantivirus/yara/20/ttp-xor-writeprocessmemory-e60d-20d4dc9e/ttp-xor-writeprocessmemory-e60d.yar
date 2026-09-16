rule TTP_XOR_WriteProcessMemory_e60d {
  strings:
    $key_e60d = { b1 7f [2] 83 5d [2] 85 68 [2] ab 68 [2] 94 74 }

  condition:
    any of them
}