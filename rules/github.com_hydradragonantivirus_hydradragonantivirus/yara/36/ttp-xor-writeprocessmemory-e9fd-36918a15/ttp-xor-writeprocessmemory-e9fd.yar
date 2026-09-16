rule TTP_XOR_WriteProcessMemory_e9fd {
  strings:
    $key_e9fd = { be 8f [2] 8c ad [2] 8a 98 [2] a4 98 [2] 9b 84 }

  condition:
    any of them
}