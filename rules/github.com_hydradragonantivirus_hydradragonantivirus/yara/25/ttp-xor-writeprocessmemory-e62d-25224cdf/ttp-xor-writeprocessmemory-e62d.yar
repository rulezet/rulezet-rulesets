rule TTP_XOR_WriteProcessMemory_e62d {
  strings:
    $key_e62d = { b1 5f [2] 83 7d [2] 85 48 [2] ab 48 [2] 94 54 }

  condition:
    any of them
}