rule TTP_XOR_WriteProcessMemory_d8fd {
  strings:
    $key_d8fd = { 8f 8f [2] bd ad [2] bb 98 [2] 95 98 [2] aa 84 }

  condition:
    any of them
}