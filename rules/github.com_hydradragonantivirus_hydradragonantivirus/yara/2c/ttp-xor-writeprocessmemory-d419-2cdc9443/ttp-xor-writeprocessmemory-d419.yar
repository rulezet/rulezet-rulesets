rule TTP_XOR_WriteProcessMemory_d419 {
  strings:
    $key_d419 = { 83 6b [2] b1 49 [2] b7 7c [2] 99 7c [2] a6 60 }

  condition:
    any of them
}