rule TTP_XOR_WriteProcessMemory_497e {
  strings:
    $key_497e = { 1e 0c [2] 2c 2e [2] 2a 1b [2] 04 1b [2] 3b 07 }

  condition:
    any of them
}