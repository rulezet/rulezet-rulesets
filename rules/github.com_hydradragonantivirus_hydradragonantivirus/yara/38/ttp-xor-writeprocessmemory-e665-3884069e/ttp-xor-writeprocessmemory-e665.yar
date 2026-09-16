rule TTP_XOR_WriteProcessMemory_e665 {
  strings:
    $key_e665 = { b1 17 [2] 83 35 [2] 85 00 [2] ab 00 [2] 94 1c }

  condition:
    any of them
}