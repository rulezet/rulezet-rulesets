rule TTP_XOR_WriteProcessMemory_d0f9 {
  strings:
    $key_d0f9 = { 87 8b [2] b5 a9 [2] b3 9c [2] 9d 9c [2] a2 80 }

  condition:
    any of them
}