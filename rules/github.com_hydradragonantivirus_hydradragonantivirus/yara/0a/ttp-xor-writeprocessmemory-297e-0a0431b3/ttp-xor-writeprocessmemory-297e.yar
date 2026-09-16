rule TTP_XOR_WriteProcessMemory_297e {
  strings:
    $key_297e = { 7e 0c [2] 4c 2e [2] 4a 1b [2] 64 1b [2] 5b 07 }

  condition:
    any of them
}