rule TTP_XOR_WriteProcessMemory_cb83 {
  strings:
    $key_cb83 = { 9c f1 [2] ae d3 [2] a8 e6 [2] 86 e6 [2] b9 fa }

  condition:
    any of them
}