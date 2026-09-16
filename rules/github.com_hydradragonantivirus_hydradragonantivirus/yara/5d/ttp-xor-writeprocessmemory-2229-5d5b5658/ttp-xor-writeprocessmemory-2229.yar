rule TTP_XOR_WriteProcessMemory_2229 {
  strings:
    $key_2229 = { 75 5b [2] 47 79 [2] 41 4c [2] 6f 4c [2] 50 50 }

  condition:
    any of them
}