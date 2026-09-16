rule TTP_XOR_WriteProcessMemory_d4ee {
  strings:
    $key_d4ee = { 83 9c [2] b1 be [2] b7 8b [2] 99 8b [2] a6 97 }

  condition:
    any of them
}