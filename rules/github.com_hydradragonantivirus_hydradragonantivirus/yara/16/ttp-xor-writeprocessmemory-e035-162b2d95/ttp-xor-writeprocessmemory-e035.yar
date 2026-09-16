rule TTP_XOR_WriteProcessMemory_e035 {
  strings:
    $key_e035 = { b7 47 [2] 85 65 [2] 83 50 [2] ad 50 [2] 92 4c }

  condition:
    any of them
}