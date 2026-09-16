rule TTP_XOR_WriteProcessMemory_0035 {
  strings:
    $key_0035 = { 57 47 [2] 65 65 [2] 63 50 [2] 4d 50 [2] 72 4c }

  condition:
    any of them
}