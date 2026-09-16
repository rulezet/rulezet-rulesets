rule TTP_XOR_WriteProcessMemory_c8bc {
  strings:
    $key_c8bc = { 9f ce [2] ad ec [2] ab d9 [2] 85 d9 [2] ba c5 }

  condition:
    any of them
}