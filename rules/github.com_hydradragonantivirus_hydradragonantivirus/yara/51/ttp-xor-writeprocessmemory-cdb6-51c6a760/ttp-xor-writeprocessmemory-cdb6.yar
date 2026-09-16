rule TTP_XOR_WriteProcessMemory_cdb6 {
  strings:
    $key_cdb6 = { 9a c4 [2] a8 e6 [2] ae d3 [2] 80 d3 [2] bf cf }

  condition:
    any of them
}