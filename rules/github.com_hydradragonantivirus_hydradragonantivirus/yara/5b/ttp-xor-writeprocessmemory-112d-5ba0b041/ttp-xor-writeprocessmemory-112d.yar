rule TTP_XOR_WriteProcessMemory_112d {
  strings:
    $key_112d = { 46 5f [2] 74 7d [2] 72 48 [2] 5c 48 [2] 63 54 }

  condition:
    any of them
}