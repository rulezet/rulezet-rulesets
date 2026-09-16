rule TTP_XOR_WriteProcessMemory_e554 {
  strings:
    $key_e554 = { b2 26 [2] 80 04 [2] 86 31 [2] a8 31 [2] 97 2d }

  condition:
    any of them
}