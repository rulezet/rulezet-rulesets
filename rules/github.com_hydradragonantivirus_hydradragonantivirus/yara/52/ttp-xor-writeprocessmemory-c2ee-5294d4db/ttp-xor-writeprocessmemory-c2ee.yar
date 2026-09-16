rule TTP_XOR_WriteProcessMemory_c2ee {
  strings:
    $key_c2ee = { 95 9c [2] a7 be [2] a1 8b [2] 8f 8b [2] b0 97 }

  condition:
    any of them
}