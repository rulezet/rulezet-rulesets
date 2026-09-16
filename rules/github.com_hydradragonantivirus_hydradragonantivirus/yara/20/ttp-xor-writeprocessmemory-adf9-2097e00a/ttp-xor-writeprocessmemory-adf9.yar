rule TTP_XOR_WriteProcessMemory_adf9 {
  strings:
    $key_adf9 = { fa 8b [2] c8 a9 [2] ce 9c [2] e0 9c [2] df 80 }

  condition:
    any of them
}