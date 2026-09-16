rule TTP_XOR_WriteProcessMemory_c6fd {
  strings:
    $key_c6fd = { 91 8f [2] a3 ad [2] a5 98 [2] 8b 98 [2] b4 84 }

  condition:
    any of them
}