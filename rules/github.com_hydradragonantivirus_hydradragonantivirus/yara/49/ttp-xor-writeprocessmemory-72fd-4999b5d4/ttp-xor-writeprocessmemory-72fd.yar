rule TTP_XOR_WriteProcessMemory_72fd {
  strings:
    $key_72fd = { 25 8f [2] 17 ad [2] 11 98 [2] 3f 98 [2] 00 84 }

  condition:
    any of them
}