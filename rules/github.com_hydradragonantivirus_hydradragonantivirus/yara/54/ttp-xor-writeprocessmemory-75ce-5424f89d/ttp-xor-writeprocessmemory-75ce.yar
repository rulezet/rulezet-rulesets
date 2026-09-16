rule TTP_XOR_WriteProcessMemory_75ce {
  strings:
    $key_75ce = { 22 bc [2] 10 9e [2] 16 ab [2] 38 ab [2] 07 b7 }

  condition:
    any of them
}