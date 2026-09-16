rule TTP_XOR_WriteProcessMemory_d0fd {
  strings:
    $key_d0fd = { 87 8f [2] b5 ad [2] b3 98 [2] 9d 98 [2] a2 84 }

  condition:
    any of them
}