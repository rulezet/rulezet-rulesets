rule TTP_XOR_WriteProcessMemory_f819 {
  strings:
    $key_f819 = { af 6b [2] 9d 49 [2] 9b 7c [2] b5 7c [2] 8a 60 }

  condition:
    any of them
}