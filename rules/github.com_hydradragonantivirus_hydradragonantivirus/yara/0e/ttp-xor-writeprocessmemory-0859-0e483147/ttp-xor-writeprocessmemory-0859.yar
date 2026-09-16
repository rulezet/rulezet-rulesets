rule TTP_XOR_WriteProcessMemory_0859 {
  strings:
    $key_0859 = { 5f 2b [2] 6d 09 [2] 6b 3c [2] 45 3c [2] 7a 20 }

  condition:
    any of them
}