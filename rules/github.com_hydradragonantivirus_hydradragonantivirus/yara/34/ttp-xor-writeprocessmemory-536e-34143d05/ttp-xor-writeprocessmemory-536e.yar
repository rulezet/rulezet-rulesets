rule TTP_XOR_WriteProcessMemory_536e {
  strings:
    $key_536e = { 04 1c [2] 36 3e [2] 30 0b [2] 1e 0b [2] 21 17 }

  condition:
    any of them
}