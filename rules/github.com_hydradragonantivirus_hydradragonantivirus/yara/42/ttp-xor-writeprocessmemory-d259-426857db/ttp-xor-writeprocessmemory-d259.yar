rule TTP_XOR_WriteProcessMemory_d259 {
  strings:
    $key_d259 = { 85 2b [2] b7 09 [2] b1 3c [2] 9f 3c [2] a0 20 }

  condition:
    any of them
}