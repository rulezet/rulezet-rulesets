rule TTP_XOR_WriteProcessMemory_173d {
  strings:
    $key_173d = { 40 4f [2] 72 6d [2] 74 58 [2] 5a 58 [2] 65 44 }

  condition:
    any of them
}