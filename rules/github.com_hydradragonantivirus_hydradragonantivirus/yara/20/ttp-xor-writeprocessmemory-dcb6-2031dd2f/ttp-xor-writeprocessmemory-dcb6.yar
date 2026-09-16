rule TTP_XOR_WriteProcessMemory_dcb6 {
  strings:
    $key_dcb6 = { 8b c4 [2] b9 e6 [2] bf d3 [2] 91 d3 [2] ae cf }

  condition:
    any of them
}