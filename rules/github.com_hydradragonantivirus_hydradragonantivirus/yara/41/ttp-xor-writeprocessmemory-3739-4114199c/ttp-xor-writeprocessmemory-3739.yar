rule TTP_XOR_WriteProcessMemory_3739 {
  strings:
    $key_3739 = { 60 4b [2] 52 69 [2] 54 5c [2] 7a 5c [2] 45 40 }

  condition:
    any of them
}