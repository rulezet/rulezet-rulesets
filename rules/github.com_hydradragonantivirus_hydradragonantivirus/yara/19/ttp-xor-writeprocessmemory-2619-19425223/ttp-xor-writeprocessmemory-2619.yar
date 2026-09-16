rule TTP_XOR_WriteProcessMemory_2619 {
  strings:
    $key_2619 = { 71 6b [2] 43 49 [2] 45 7c [2] 6b 7c [2] 54 60 }

  condition:
    any of them
}