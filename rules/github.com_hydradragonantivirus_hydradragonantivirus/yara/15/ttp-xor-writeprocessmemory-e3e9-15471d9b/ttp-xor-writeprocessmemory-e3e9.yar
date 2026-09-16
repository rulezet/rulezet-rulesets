rule TTP_XOR_WriteProcessMemory_e3e9 {
  strings:
    $key_e3e9 = { b4 9b [2] 86 b9 [2] 80 8c [2] ae 8c [2] 91 90 }

  condition:
    any of them
}