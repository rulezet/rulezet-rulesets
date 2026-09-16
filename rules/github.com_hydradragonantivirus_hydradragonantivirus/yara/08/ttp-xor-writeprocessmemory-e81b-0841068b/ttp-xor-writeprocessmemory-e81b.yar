rule TTP_XOR_WriteProcessMemory_e81b {
  strings:
    $key_e81b = { bf 69 [2] 8d 4b [2] 8b 7e [2] a5 7e [2] 9a 62 }

  condition:
    any of them
}