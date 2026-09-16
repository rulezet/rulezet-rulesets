rule TTP_XOR_WriteProcessMemory_d53c {
  strings:
    $key_d53c = { 82 4e [2] b0 6c [2] b6 59 [2] 98 59 [2] a7 45 }

  condition:
    any of them
}