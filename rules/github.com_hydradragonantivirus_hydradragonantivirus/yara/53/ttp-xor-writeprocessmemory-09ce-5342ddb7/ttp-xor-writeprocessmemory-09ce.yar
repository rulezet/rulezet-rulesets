rule TTP_XOR_WriteProcessMemory_09ce {
  strings:
    $key_09ce = { 5e bc [2] 6c 9e [2] 6a ab [2] 44 ab [2] 7b b7 }

  condition:
    any of them
}