rule TTP_XOR_WriteProcessMemory_effb {
  strings:
    $key_effb = { b8 89 [2] 8a ab [2] 8c 9e [2] a2 9e [2] 9d 82 }

  condition:
    any of them
}