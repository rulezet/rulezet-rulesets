rule TTP_XOR_WriteProcessMemory_ebe3 {
  strings:
    $key_ebe3 = { bc 91 [2] 8e b3 [2] 88 86 [2] a6 86 [2] 99 9a }

  condition:
    any of them
}