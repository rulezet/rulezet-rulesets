rule TTP_XOR_WriteProcessMemory_e369 {
  strings:
    $key_e369 = { b4 1b [2] 86 39 [2] 80 0c [2] ae 0c [2] 91 10 }

  condition:
    any of them
}