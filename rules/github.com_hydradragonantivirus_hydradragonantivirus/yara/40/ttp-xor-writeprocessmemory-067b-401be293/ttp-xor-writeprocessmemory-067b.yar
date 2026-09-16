rule TTP_XOR_WriteProcessMemory_067b {
  strings:
    $key_067b = { 51 09 [2] 63 2b [2] 65 1e [2] 4b 1e [2] 74 02 }

  condition:
    any of them
}