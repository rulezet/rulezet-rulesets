rule TTP_XOR_WriteProcessMemory_c8ce {
  strings:
    $key_c8ce = { 9f bc [2] ad 9e [2] ab ab [2] 85 ab [2] ba b7 }

  condition:
    any of them
}