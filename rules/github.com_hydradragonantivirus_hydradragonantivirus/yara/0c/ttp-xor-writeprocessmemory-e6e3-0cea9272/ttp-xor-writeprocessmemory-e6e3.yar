rule TTP_XOR_WriteProcessMemory_e6e3 {
  strings:
    $key_e6e3 = { b1 91 [2] 83 b3 [2] 85 86 [2] ab 86 [2] 94 9a }

  condition:
    any of them
}