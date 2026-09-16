rule TTP_XOR_WriteProcessMemory_e359 {
  strings:
    $key_e359 = { b4 2b [2] 86 09 [2] 80 3c [2] ae 3c [2] 91 20 }

  condition:
    any of them
}