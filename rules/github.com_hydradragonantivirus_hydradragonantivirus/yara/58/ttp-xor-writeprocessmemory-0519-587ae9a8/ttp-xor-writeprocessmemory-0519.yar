rule TTP_XOR_WriteProcessMemory_0519 {
  strings:
    $key_0519 = { 52 6b [2] 60 49 [2] 66 7c [2] 48 7c [2] 77 60 }

  condition:
    any of them
}