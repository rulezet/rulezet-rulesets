rule TTP_XOR_WriteProcessMemory_112c {
  strings:
    $key_112c = { 46 5e [2] 74 7c [2] 72 49 [2] 5c 49 [2] 63 55 }

  condition:
    any of them
}