rule TTP_XOR_WriteProcessMemory_c5ee {
  strings:
    $key_c5ee = { 92 9c [2] a0 be [2] a6 8b [2] 88 8b [2] b7 97 }

  condition:
    any of them
}