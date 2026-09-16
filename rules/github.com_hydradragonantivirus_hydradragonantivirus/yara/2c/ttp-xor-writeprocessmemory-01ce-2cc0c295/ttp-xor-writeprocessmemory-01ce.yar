rule TTP_XOR_WriteProcessMemory_01ce {
  strings:
    $key_01ce = { 56 bc [2] 64 9e [2] 62 ab [2] 4c ab [2] 73 b7 }

  condition:
    any of them
}