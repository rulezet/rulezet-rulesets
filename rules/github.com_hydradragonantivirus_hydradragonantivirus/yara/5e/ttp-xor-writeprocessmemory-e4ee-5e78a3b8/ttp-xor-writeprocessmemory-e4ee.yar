rule TTP_XOR_WriteProcessMemory_e4ee {
  strings:
    $key_e4ee = { b3 9c [2] 81 be [2] 87 8b [2] a9 8b [2] 96 97 }

  condition:
    any of them
}