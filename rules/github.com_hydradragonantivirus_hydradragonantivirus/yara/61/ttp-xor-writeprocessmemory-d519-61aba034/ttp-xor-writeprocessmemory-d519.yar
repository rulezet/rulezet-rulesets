rule TTP_XOR_WriteProcessMemory_d519 {
  strings:
    $key_d519 = { 82 6b [2] b0 49 [2] b6 7c [2] 98 7c [2] a7 60 }

  condition:
    any of them
}