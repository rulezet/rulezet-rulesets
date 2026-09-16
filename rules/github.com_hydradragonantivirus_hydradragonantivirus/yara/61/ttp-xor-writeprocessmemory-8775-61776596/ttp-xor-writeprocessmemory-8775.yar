rule TTP_XOR_WriteProcessMemory_8775 {
  strings:
    $key_8775 = { d0 07 [2] e2 25 [2] e4 10 [2] ca 10 [2] f5 0c }

  condition:
    any of them
}