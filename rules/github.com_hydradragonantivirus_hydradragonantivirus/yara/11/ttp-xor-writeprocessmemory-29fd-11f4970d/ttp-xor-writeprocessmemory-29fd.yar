rule TTP_XOR_WriteProcessMemory_29fd {
  strings:
    $key_29fd = { 7e 8f [2] 4c ad [2] 4a 98 [2] 64 98 [2] 5b 84 }

  condition:
    any of them
}