rule TTP_XOR_WriteProcessMemory_e61c {
  strings:
    $key_e61c = { b1 6e [2] 83 4c [2] 85 79 [2] ab 79 [2] 94 65 }

  condition:
    any of them
}