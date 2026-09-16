rule TTP_XOR_WriteProcessMemory_dcb3 {
  strings:
    $key_dcb3 = { 8b c1 [2] b9 e3 [2] bf d6 [2] 91 d6 [2] ae ca }

  condition:
    any of them
}