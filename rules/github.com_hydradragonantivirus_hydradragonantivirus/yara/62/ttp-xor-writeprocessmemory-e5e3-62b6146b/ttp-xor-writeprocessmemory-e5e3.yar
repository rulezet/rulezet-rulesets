rule TTP_XOR_WriteProcessMemory_e5e3 {
  strings:
    $key_e5e3 = { b2 91 [2] 80 b3 [2] 86 86 [2] a8 86 [2] 97 9a }

  condition:
    any of them
}