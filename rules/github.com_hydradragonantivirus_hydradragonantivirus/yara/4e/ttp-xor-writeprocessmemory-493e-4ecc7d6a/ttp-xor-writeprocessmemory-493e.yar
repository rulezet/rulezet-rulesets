rule TTP_XOR_WriteProcessMemory_493e {
  strings:
    $key_493e = { 1e 4c [2] 2c 6e [2] 2a 5b [2] 04 5b [2] 3b 47 }

  condition:
    any of them
}