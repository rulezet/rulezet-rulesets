rule TTP_XOR_WriteProcessMemory_4bfd {
  strings:
    $key_4bfd = { 1c 8f [2] 2e ad [2] 28 98 [2] 06 98 [2] 39 84 }

  condition:
    any of them
}