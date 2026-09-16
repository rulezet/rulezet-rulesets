rule TTP_XOR_WriteProcessMemory_72ee {
  strings:
    $key_72ee = { 25 9c [2] 17 be [2] 11 8b [2] 3f 8b [2] 00 97 }

  condition:
    any of them
}