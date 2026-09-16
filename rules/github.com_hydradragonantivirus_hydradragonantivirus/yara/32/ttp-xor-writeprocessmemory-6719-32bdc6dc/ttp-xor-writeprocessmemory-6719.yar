rule TTP_XOR_WriteProcessMemory_6719 {
  strings:
    $key_6719 = { 30 6b [2] 02 49 [2] 04 7c [2] 2a 7c [2] 15 60 }

  condition:
    any of them
}