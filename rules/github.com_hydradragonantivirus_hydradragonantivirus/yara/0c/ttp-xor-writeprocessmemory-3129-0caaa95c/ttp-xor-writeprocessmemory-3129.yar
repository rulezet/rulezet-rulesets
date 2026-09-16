rule TTP_XOR_WriteProcessMemory_3129 {
  strings:
    $key_3129 = { 66 5b [2] 54 79 [2] 52 4c [2] 7c 4c [2] 43 50 }

  condition:
    any of them
}