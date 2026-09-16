rule TTP_XOR_WriteProcessMemory_e319 {
  strings:
    $key_e319 = { b4 6b [2] 86 49 [2] 80 7c [2] ae 7c [2] 91 60 }

  condition:
    any of them
}