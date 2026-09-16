rule TTP_XOR_WriteProcessMemory_057c {
  strings:
    $key_057c = { 52 0e [2] 60 2c [2] 66 19 [2] 48 19 [2] 77 05 }

  condition:
    any of them
}