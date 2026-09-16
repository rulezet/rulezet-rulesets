rule TTP_XOR_WriteProcessMemory_59fd {
  strings:
    $key_59fd = { 0e 8f [2] 3c ad [2] 3a 98 [2] 14 98 [2] 2b 84 }

  condition:
    any of them
}