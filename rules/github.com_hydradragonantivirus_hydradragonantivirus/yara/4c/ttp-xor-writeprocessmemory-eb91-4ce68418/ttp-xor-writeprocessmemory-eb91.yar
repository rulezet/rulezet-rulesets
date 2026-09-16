rule TTP_XOR_WriteProcessMemory_eb91 {
  strings:
    $key_eb91 = { bc e3 [2] 8e c1 [2] 88 f4 [2] a6 f4 [2] 99 e8 }

  condition:
    any of them
}