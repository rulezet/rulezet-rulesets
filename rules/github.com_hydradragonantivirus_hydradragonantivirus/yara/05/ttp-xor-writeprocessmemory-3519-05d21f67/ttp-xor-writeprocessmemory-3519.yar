rule TTP_XOR_WriteProcessMemory_3519 {
  strings:
    $key_3519 = { 62 6b [2] 50 49 [2] 56 7c [2] 78 7c [2] 47 60 }

  condition:
    any of them
}