rule TTP_XOR_WriteProcessMemory_517e {
  strings:
    $key_517e = { 06 0c [2] 34 2e [2] 32 1b [2] 1c 1b [2] 23 07 }

  condition:
    any of them
}