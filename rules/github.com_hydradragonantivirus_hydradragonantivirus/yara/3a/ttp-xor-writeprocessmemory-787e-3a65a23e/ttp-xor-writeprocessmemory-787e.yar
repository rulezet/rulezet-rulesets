rule TTP_XOR_WriteProcessMemory_787e {
  strings:
    $key_787e = { 2f 0c [2] 1d 2e [2] 1b 1b [2] 35 1b [2] 0a 07 }

  condition:
    any of them
}