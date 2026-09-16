rule TTP_XOR_WriteProcessMemory_24fd {
  strings:
    $key_24fd = { 73 8f [2] 41 ad [2] 47 98 [2] 69 98 [2] 56 84 }

  condition:
    any of them
}