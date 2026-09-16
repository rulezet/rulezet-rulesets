rule TTP_XOR_WriteProcessMemory_314e {
  strings:
    $key_314e = { 66 3c [2] 54 1e [2] 52 2b [2] 7c 2b [2] 43 37 }

  condition:
    any of them
}