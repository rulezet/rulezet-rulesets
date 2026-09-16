rule TTP_XOR_WriteProcessMemory_e5f4 {
  strings:
    $key_e5f4 = { b2 86 [2] 80 a4 [2] 86 91 [2] a8 91 [2] 97 8d }

  condition:
    any of them
}