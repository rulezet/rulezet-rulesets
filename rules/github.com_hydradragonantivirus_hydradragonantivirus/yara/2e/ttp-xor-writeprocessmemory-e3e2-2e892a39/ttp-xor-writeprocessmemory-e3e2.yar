rule TTP_XOR_WriteProcessMemory_e3e2 {
  strings:
    $key_e3e2 = { b4 90 [2] 86 b2 [2] 80 87 [2] ae 87 [2] 91 9b }

  condition:
    any of them
}