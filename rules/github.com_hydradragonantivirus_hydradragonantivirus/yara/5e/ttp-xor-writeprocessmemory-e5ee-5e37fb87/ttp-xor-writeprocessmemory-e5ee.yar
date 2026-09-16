rule TTP_XOR_WriteProcessMemory_e5ee {
  strings:
    $key_e5ee = { b2 9c [2] 80 be [2] 86 8b [2] a8 8b [2] 97 97 }

  condition:
    any of them
}