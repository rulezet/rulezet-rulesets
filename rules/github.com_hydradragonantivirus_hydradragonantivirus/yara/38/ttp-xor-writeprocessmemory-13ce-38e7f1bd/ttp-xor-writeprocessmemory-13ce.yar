rule TTP_XOR_WriteProcessMemory_13ce {
  strings:
    $key_13ce = { 44 bc [2] 76 9e [2] 70 ab [2] 5e ab [2] 61 b7 }

  condition:
    any of them
}