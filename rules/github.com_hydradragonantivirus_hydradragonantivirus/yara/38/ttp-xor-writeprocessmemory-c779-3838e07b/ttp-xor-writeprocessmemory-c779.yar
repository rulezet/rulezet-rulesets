rule TTP_XOR_WriteProcessMemory_c779 {
  strings:
    $key_c779 = { 90 0b [2] a2 29 [2] a4 1c [2] 8a 1c [2] b5 00 }

  condition:
    any of them
}