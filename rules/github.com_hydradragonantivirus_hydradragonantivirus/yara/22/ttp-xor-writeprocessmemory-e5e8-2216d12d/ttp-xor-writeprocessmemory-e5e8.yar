rule TTP_XOR_WriteProcessMemory_e5e8 {
  strings:
    $key_e5e8 = { b2 9a [2] 80 b8 [2] 86 8d [2] a8 8d [2] 97 91 }

  condition:
    any of them
}