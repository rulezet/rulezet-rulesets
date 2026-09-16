rule TTP_XOR_WriteProcessMemory_8575 {
  strings:
    $key_8575 = { d2 07 [2] e0 25 [2] e6 10 [2] c8 10 [2] f7 0c }

  condition:
    any of them
}