rule TTP_XOR_WriteProcessMemory_0a19 {
  strings:
    $key_0a19 = { 5d 6b [2] 6f 49 [2] 69 7c [2] 47 7c [2] 78 60 }

  condition:
    any of them
}