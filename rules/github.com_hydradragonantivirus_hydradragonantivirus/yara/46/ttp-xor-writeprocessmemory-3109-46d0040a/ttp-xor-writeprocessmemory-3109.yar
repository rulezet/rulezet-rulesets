rule TTP_XOR_WriteProcessMemory_3109 {
  strings:
    $key_3109 = { 66 7b [2] 54 59 [2] 52 6c [2] 7c 6c [2] 43 70 }

  condition:
    any of them
}