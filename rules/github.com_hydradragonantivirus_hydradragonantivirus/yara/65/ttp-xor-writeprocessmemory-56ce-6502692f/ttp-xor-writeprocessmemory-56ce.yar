rule TTP_XOR_WriteProcessMemory_56ce {
  strings:
    $key_56ce = { 01 bc [2] 33 9e [2] 35 ab [2] 1b ab [2] 24 b7 }

  condition:
    any of them
}