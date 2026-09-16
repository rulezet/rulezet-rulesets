rule TTP_XOR_WriteProcessMemory_65ce {
  strings:
    $key_65ce = { 32 bc [2] 00 9e [2] 06 ab [2] 28 ab [2] 17 b7 }

  condition:
    any of them
}