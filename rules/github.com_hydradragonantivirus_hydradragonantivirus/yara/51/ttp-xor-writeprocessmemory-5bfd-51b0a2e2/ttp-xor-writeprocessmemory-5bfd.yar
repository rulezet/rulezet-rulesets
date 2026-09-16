rule TTP_XOR_WriteProcessMemory_5bfd {
  strings:
    $key_5bfd = { 0c 8f [2] 3e ad [2] 38 98 [2] 16 98 [2] 29 84 }

  condition:
    any of them
}