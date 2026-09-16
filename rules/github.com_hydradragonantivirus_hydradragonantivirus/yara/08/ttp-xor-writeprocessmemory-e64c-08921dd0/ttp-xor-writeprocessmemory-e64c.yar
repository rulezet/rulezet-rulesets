rule TTP_XOR_WriteProcessMemory_e64c {
  strings:
    $key_e64c = { b1 3e [2] 83 1c [2] 85 29 [2] ab 29 [2] 94 35 }

  condition:
    any of them
}