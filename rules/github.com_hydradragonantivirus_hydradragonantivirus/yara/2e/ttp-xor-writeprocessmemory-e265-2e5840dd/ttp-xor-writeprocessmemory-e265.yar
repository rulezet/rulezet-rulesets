rule TTP_XOR_WriteProcessMemory_e265 {
  strings:
    $key_e265 = { b5 17 [2] 87 35 [2] 81 00 [2] af 00 [2] 90 1c }

  condition:
    any of them
}