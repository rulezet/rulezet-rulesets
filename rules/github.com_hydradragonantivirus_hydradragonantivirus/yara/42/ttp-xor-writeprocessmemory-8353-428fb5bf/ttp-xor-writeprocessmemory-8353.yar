rule TTP_XOR_WriteProcessMemory_8353 {
  strings:
    $key_8353 = { d4 21 [2] e6 03 [2] e0 36 [2] ce 36 [2] f1 2a }

  condition:
    any of them
}