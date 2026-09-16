rule TTP_XOR_WriteProcessMemory_fceb {
  strings:
    $key_fceb = { ab 99 [2] 99 bb [2] 9f 8e [2] b1 8e [2] 8e 92 }

  condition:
    any of them
}