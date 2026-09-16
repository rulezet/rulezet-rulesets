rule TTP_XOR_WriteProcessMemory_0109 {
  strings:
    $key_0109 = { 56 7b [2] 64 59 [2] 62 6c [2] 4c 6c [2] 73 70 }

  condition:
    any of them
}