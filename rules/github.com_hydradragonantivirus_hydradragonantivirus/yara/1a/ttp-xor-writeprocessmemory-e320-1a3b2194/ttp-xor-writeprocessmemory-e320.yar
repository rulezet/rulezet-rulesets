rule TTP_XOR_WriteProcessMemory_e320 {
  strings:
    $key_e320 = { b4 52 [2] 86 70 [2] 80 45 [2] ae 45 [2] 91 59 }

  condition:
    any of them
}