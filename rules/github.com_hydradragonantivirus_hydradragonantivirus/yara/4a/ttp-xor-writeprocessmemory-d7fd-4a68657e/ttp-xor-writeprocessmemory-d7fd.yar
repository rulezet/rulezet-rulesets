rule TTP_XOR_WriteProcessMemory_d7fd {
  strings:
    $key_d7fd = { 80 8f [2] b2 ad [2] b4 98 [2] 9a 98 [2] a5 84 }

  condition:
    any of them
}