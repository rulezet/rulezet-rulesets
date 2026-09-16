rule TTP_XOR_WriteProcessMemory_6c7e {
  strings:
    $key_6c7e = { 3b 0c [2] 09 2e [2] 0f 1b [2] 21 1b [2] 1e 07 }

  condition:
    any of them
}