rule TTP_XOR_WriteProcessMemory_87e8 {
  strings:
    $key_87e8 = { d0 9a [2] e2 b8 [2] e4 8d [2] ca 8d [2] f5 91 }

  condition:
    any of them
}