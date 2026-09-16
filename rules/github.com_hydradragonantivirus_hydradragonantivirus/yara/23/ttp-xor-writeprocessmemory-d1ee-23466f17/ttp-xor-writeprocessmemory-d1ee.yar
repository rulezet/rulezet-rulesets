rule TTP_XOR_WriteProcessMemory_d1ee {
  strings:
    $key_d1ee = { 86 9c [2] b4 be [2] b2 8b [2] 9c 8b [2] a3 97 }

  condition:
    any of them
}