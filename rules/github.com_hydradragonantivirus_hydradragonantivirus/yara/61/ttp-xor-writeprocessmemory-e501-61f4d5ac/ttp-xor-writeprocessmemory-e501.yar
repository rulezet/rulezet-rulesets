rule TTP_XOR_WriteProcessMemory_e501 {
  strings:
    $key_e501 = { b2 73 [2] 80 51 [2] 86 64 [2] a8 64 [2] 97 78 }

  condition:
    any of them
}