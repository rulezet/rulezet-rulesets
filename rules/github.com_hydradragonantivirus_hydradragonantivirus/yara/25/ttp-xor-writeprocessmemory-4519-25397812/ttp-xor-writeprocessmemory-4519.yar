rule TTP_XOR_WriteProcessMemory_4519 {
  strings:
    $key_4519 = { 12 6b [2] 20 49 [2] 26 7c [2] 08 7c [2] 37 60 }

  condition:
    any of them
}