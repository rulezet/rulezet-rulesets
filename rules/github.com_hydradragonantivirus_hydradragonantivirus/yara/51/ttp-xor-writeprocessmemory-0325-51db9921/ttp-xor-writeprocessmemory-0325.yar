rule TTP_XOR_WriteProcessMemory_0325 {
  strings:
    $key_0325 = { 54 57 [2] 66 75 [2] 60 40 [2] 4e 40 [2] 71 5c }

  condition:
    any of them
}