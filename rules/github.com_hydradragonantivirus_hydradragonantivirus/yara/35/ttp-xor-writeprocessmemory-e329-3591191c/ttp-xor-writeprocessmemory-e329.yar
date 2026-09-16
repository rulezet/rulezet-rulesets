rule TTP_XOR_WriteProcessMemory_e329 {
  strings:
    $key_e329 = { b4 5b [2] 86 79 [2] 80 4c [2] ae 4c [2] 91 50 }

  condition:
    any of them
}