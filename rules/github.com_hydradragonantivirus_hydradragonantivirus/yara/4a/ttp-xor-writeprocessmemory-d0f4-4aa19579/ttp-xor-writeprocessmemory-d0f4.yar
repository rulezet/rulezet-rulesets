rule TTP_XOR_WriteProcessMemory_d0f4 {
  strings:
    $key_d0f4 = { 87 86 [2] b5 a4 [2] b3 91 [2] 9d 91 [2] a2 8d }

  condition:
    any of them
}