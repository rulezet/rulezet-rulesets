rule TTP_XOR_WriteProcessMemory_e43c {
  strings:
    $key_e43c = { b3 4e [2] 81 6c [2] 87 59 [2] a9 59 [2] 96 45 }

  condition:
    any of them
}