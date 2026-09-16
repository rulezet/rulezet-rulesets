rule TTP_XOR_WriteProcessMemory_3229 {
  strings:
    $key_3229 = { 65 5b [2] 57 79 [2] 51 4c [2] 7f 4c [2] 40 50 }

  condition:
    any of them
}