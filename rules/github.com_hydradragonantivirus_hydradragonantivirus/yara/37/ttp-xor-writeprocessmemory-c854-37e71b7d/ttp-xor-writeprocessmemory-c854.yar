rule TTP_XOR_WriteProcessMemory_c854 {
  strings:
    $key_c854 = { 9f 26 [2] ad 04 [2] ab 31 [2] 85 31 [2] ba 2d }

  condition:
    any of them
}