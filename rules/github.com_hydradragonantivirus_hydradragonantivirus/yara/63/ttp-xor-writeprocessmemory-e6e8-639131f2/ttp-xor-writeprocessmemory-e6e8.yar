rule TTP_XOR_WriteProcessMemory_e6e8 {
  strings:
    $key_e6e8 = { b1 9a [2] 83 b8 [2] 85 8d [2] ab 8d [2] 94 91 }

  condition:
    any of them
}