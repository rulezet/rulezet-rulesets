rule TTP_XOR_WriteProcessMemory_c824 {
  strings:
    $key_c824 = { 9f 56 [2] ad 74 [2] ab 41 [2] 85 41 [2] ba 5d }

  condition:
    any of them
}