rule TTP_XOR_WriteProcessMemory_cec9 {
  strings:
    $key_cec9 = { 99 bb [2] ab 99 [2] ad ac [2] 83 ac [2] bc b0 }

  condition:
    any of them
}