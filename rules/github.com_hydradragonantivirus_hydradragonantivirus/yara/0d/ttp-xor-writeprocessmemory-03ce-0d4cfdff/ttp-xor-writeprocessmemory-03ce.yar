rule TTP_XOR_WriteProcessMemory_03ce {
  strings:
    $key_03ce = { 54 bc [2] 66 9e [2] 60 ab [2] 4e ab [2] 71 b7 }

  condition:
    any of them
}