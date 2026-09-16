rule TTP_XOR_WriteProcessMemory_6919 {
  strings:
    $key_6919 = { 3e 6b [2] 0c 49 [2] 0a 7c [2] 24 7c [2] 1b 60 }

  condition:
    any of them
}