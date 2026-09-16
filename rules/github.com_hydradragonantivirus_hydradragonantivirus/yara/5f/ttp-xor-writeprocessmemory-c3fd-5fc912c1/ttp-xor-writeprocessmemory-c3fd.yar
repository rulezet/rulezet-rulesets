rule TTP_XOR_WriteProcessMemory_c3fd {
  strings:
    $key_c3fd = { 94 8f [2] a6 ad [2] a0 98 [2] 8e 98 [2] b1 84 }

  condition:
    any of them
}