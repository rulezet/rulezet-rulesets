rule TTP_XOR_WriteProcessMemory_ade1 {
  strings:
    $key_ade1 = { fa 93 [2] c8 b1 [2] ce 84 [2] e0 84 [2] df 98 }

  condition:
    any of them
}