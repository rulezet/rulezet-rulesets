rule TTP_XOR_WriteProcessMemory_e3b6 {
  strings:
    $key_e3b6 = { b4 c4 [2] 86 e6 [2] 80 d3 [2] ae d3 [2] 91 cf }

  condition:
    any of them
}