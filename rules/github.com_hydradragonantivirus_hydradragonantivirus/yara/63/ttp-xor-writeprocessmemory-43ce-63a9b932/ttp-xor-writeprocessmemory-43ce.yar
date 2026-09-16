rule TTP_XOR_WriteProcessMemory_43ce {
  strings:
    $key_43ce = { 14 bc [2] 26 9e [2] 20 ab [2] 0e ab [2] 31 b7 }

  condition:
    any of them
}