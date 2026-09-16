rule TTP_XOR_WriteProcessMemory_397b {
  strings:
    $key_397b = { 6e 09 [2] 5c 2b [2] 5a 1e [2] 74 1e [2] 4b 02 }

  condition:
    any of them
}