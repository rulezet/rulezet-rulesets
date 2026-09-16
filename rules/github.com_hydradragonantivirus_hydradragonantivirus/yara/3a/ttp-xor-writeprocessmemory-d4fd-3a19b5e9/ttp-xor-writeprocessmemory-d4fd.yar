rule TTP_XOR_WriteProcessMemory_d4fd {
  strings:
    $key_d4fd = { 83 8f [2] b1 ad [2] b7 98 [2] 99 98 [2] a6 84 }

  condition:
    any of them
}