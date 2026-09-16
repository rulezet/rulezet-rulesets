rule TTP_XOR_WriteProcessMemory_0119 {
  strings:
    $key_0119 = { 56 6b [2] 64 49 [2] 62 7c [2] 4c 7c [2] 73 60 }

  condition:
    any of them
}