rule TTP_XOR_WriteProcessMemory_66ce {
  strings:
    $key_66ce = { 31 bc [2] 03 9e [2] 05 ab [2] 2b ab [2] 14 b7 }

  condition:
    any of them
}