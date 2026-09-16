rule TTP_XOR_WriteProcessMemory_adf8 {
  strings:
    $key_adf8 = { fa 8a [2] c8 a8 [2] ce 9d [2] e0 9d [2] df 81 }

  condition:
    any of them
}