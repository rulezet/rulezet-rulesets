rule TTP_XOR_WriteProcessMemory_c719 {
  strings:
    $key_c719 = { 90 6b [2] a2 49 [2] a4 7c [2] 8a 7c [2] b5 60 }

  condition:
    any of them
}