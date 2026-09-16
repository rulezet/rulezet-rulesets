rule TTP_XOR_WriteProcessMemory_2dec {
  strings:
    $key_2dec = { 7a 9e [2] 48 bc [2] 4e 89 [2] 60 89 [2] 5f 95 }

  condition:
    any of them
}