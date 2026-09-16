rule TTP_XOR_WriteProcessMemory_87ee {
  strings:
    $key_87ee = { d0 9c [2] e2 be [2] e4 8b [2] ca 8b [2] f5 97 }

  condition:
    any of them
}