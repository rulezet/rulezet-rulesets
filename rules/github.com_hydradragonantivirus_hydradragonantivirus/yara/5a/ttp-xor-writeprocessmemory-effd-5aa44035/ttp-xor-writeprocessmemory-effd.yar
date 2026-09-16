rule TTP_XOR_WriteProcessMemory_effd {
  strings:
    $key_effd = { b8 8f [2] 8a ad [2] 8c 98 [2] a2 98 [2] 9d 84 }

  condition:
    any of them
}