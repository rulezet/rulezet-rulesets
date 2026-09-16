rule TTP_XOR_WriteProcessMemory_8f16 {
  strings:
    $key_8f16 = { d8 64 [2] ea 46 [2] ec 73 [2] c2 73 [2] fd 6f }

  condition:
    any of them
}