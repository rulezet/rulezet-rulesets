rule TTP_XOR_WriteProcessMemory_fcde {
  strings:
    $key_fcde = { ab ac [2] 99 8e [2] 9f bb [2] b1 bb [2] 8e a7 }

  condition:
    any of them
}