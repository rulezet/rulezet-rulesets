rule TTP_XOR_WriteProcessMemory_38fd {
  strings:
    $key_38fd = { 6f 8f [2] 5d ad [2] 5b 98 [2] 75 98 [2] 4a 84 }

  condition:
    any of them
}