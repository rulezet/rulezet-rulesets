rule TTP_XOR_WriteProcessMemory_314b {
  strings:
    $key_314b = { 66 39 [2] 54 1b [2] 52 2e [2] 7c 2e [2] 43 32 }

  condition:
    any of them
}