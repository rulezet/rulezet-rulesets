rule TTP_XOR_WriteProcessMemory_c7ee {
  strings:
    $key_c7ee = { 90 9c [2] a2 be [2] a4 8b [2] 8a 8b [2] b5 97 }

  condition:
    any of them
}