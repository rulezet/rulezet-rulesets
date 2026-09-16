rule TTP_XOR_WriteProcessMemory_71fd {
  strings:
    $key_71fd = { 26 8f [2] 14 ad [2] 12 98 [2] 3c 98 [2] 03 84 }

  condition:
    any of them
}