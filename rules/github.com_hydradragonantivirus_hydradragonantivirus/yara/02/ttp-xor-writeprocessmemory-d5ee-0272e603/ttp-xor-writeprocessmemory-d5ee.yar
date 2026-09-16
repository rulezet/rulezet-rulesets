rule TTP_XOR_WriteProcessMemory_d5ee {
  strings:
    $key_d5ee = { 82 9c [2] b0 be [2] b6 8b [2] 98 8b [2] a7 97 }

  condition:
    any of them
}