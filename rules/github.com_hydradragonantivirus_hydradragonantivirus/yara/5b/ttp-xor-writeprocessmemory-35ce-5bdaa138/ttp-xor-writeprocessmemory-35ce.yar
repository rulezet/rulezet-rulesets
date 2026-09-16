rule TTP_XOR_WriteProcessMemory_35ce {
  strings:
    $key_35ce = { 62 bc [2] 50 9e [2] 56 ab [2] 78 ab [2] 47 b7 }

  condition:
    any of them
}