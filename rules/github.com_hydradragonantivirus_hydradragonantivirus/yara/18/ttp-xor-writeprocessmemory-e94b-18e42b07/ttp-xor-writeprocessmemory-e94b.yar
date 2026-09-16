rule TTP_XOR_WriteProcessMemory_e94b {
  strings:
    $key_e94b = { be 39 [2] 8c 1b [2] 8a 2e [2] a4 2e [2] 9b 32 }

  condition:
    any of them
}