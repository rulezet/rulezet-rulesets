rule TTP_XOR_WriteProcessMemory_28ce {
  strings:
    $key_28ce = { 7f bc [2] 4d 9e [2] 4b ab [2] 65 ab [2] 5a b7 }

  condition:
    any of them
}