rule TTP_XOR_WriteProcessMemory_ede3 {
  strings:
    $key_ede3 = { ba 91 [2] 88 b3 [2] 8e 86 [2] a0 86 [2] 9f 9a }

  condition:
    any of them
}