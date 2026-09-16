rule TTP_XOR_WriteProcessMemory_533c {
  strings:
    $key_533c = { 04 4e [2] 36 6c [2] 30 59 [2] 1e 59 [2] 21 45 }

  condition:
    any of them
}