rule TTP_XOR_WriteProcessMemory_49fd {
  strings:
    $key_49fd = { 1e 8f [2] 2c ad [2] 2a 98 [2] 04 98 [2] 3b 84 }

  condition:
    any of them
}