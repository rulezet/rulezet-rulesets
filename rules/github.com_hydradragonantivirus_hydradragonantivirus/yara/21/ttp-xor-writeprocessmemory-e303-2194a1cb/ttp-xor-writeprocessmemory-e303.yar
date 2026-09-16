rule TTP_XOR_WriteProcessMemory_e303 {
  strings:
    $key_e303 = { b4 71 [2] 86 53 [2] 80 66 [2] ae 66 [2] 91 7a }

  condition:
    any of them
}