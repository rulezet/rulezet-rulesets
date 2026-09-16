rule TTP_XOR_WriteProcessMemory_27ce {
  strings:
    $key_27ce = { 70 bc [2] 42 9e [2] 44 ab [2] 6a ab [2] 55 b7 }

  condition:
    any of them
}