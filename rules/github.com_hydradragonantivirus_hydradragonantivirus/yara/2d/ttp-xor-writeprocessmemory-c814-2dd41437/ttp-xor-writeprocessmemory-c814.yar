rule TTP_XOR_WriteProcessMemory_c814 {
  strings:
    $key_c814 = { 9f 66 [2] ad 44 [2] ab 71 [2] 85 71 [2] ba 6d }

  condition:
    any of them
}