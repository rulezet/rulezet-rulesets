rule TTP_XOR_WriteProcessMemory_e3d5 {
  strings:
    $key_e3d5 = { b4 a7 [2] 86 85 [2] 80 b0 [2] ae b0 [2] 91 ac }

  condition:
    any of them
}