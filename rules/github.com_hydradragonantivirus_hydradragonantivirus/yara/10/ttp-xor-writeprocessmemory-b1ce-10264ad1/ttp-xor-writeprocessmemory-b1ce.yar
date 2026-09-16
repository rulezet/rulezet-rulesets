rule TTP_XOR_WriteProcessMemory_b1ce {
  strings:
    $key_b1ce = { e6 bc [2] d4 9e [2] d2 ab [2] fc ab [2] c3 b7 }

  condition:
    any of them
}