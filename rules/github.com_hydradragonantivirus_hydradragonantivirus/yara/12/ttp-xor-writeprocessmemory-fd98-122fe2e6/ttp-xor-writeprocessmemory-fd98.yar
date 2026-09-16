rule TTP_XOR_WriteProcessMemory_fd98 {
  strings:
    $key_fd98 = { aa ea [2] 98 c8 [2] 9e fd [2] b0 fd [2] 8f e1 }

  condition:
    any of them
}