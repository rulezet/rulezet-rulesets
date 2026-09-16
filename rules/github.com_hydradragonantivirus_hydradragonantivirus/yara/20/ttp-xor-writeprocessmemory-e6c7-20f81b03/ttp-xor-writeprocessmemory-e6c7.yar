rule TTP_XOR_WriteProcessMemory_e6c7 {
  strings:
    $key_e6c7 = { b1 b5 [2] 83 97 [2] 85 a2 [2] ab a2 [2] 94 be }

  condition:
    any of them
}