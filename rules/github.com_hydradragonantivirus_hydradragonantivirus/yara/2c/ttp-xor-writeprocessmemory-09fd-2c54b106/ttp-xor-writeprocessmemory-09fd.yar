rule TTP_XOR_WriteProcessMemory_09fd {
  strings:
    $key_09fd = { 5e 8f [2] 6c ad [2] 6a 98 [2] 44 98 [2] 7b 84 }

  condition:
    any of them
}