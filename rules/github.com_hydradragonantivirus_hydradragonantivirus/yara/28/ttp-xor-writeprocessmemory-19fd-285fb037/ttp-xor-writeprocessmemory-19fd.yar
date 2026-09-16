rule TTP_XOR_WriteProcessMemory_19fd {
  strings:
    $key_19fd = { 4e 8f [2] 7c ad [2] 7a 98 [2] 54 98 [2] 6b 84 }

  condition:
    any of them
}