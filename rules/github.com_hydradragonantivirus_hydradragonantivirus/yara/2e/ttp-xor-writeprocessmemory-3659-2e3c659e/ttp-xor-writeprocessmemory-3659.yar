rule TTP_XOR_WriteProcessMemory_3659 {
  strings:
    $key_3659 = { 61 2b [2] 53 09 [2] 55 3c [2] 7b 3c [2] 44 20 }

  condition:
    any of them
}