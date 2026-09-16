rule TTP_XOR_WriteProcessMemory_bc83 {
  strings:
    $key_bc83 = { eb f1 [2] d9 d3 [2] df e6 [2] f1 e6 [2] ce fa }

  condition:
    any of them
}