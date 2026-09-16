rule TTP_XOR_WriteProcessMemory_3719 {
  strings:
    $key_3719 = { 60 6b [2] 52 49 [2] 54 7c [2] 7a 7c [2] 45 60 }

  condition:
    any of them
}