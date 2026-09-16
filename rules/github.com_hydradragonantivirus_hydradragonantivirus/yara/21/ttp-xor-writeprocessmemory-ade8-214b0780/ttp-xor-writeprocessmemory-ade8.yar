rule TTP_XOR_WriteProcessMemory_ade8 {
  strings:
    $key_ade8 = { fa 9a [2] c8 b8 [2] ce 8d [2] e0 8d [2] df 91 }

  condition:
    any of them
}