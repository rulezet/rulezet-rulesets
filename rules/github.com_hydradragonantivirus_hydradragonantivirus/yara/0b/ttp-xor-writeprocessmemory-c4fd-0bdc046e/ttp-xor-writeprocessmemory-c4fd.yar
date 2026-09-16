rule TTP_XOR_WriteProcessMemory_c4fd {
  strings:
    $key_c4fd = { 93 8f [2] a1 ad [2] a7 98 [2] 89 98 [2] b6 84 }

  condition:
    any of them
}