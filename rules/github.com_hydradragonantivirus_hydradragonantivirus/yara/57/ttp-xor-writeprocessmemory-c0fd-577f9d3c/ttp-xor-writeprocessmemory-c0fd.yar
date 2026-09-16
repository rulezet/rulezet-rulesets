rule TTP_XOR_WriteProcessMemory_c0fd {
  strings:
    $key_c0fd = { 97 8f [2] a5 ad [2] a3 98 [2] 8d 98 [2] b2 84 }

  condition:
    any of them
}