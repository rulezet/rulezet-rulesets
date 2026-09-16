rule TTP_XOR_WriteProcessMemory_f829 {
  strings:
    $key_f829 = { af 5b [2] 9d 79 [2] 9b 4c [2] b5 4c [2] 8a 50 }

  condition:
    any of them
}