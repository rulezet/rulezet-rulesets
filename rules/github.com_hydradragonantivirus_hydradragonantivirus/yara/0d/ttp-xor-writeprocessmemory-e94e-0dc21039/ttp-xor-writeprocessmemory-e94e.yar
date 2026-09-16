rule TTP_XOR_WriteProcessMemory_e94e {
  strings:
    $key_e94e = { be 3c [2] 8c 1e [2] 8a 2b [2] a4 2b [2] 9b 37 }

  condition:
    any of them
}