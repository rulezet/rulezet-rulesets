rule TTP_XOR_WriteProcessMemory_25ce {
  strings:
    $key_25ce = { 72 bc [2] 40 9e [2] 46 ab [2] 68 ab [2] 57 b7 }

  condition:
    any of them
}