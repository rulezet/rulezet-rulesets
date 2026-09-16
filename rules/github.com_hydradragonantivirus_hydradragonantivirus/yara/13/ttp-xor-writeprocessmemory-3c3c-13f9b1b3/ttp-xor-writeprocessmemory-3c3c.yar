rule TTP_XOR_WriteProcessMemory_3c3c {
  strings:
    $key_3c3c = { 6b 4e [2] 59 6c [2] 5f 59 [2] 71 59 [2] 4e 45 }

  condition:
    any of them
}