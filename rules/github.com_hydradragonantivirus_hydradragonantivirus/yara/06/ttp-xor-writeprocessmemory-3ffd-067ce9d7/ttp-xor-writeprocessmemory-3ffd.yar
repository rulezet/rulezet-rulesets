rule TTP_XOR_WriteProcessMemory_3ffd {
  strings:
    $key_3ffd = { 68 8f [2] 5a ad [2] 5c 98 [2] 72 98 [2] 4d 84 }

  condition:
    any of them
}