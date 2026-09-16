rule TTP_XOR_WriteProcessMemory_cbb6 {
  strings:
    $key_cbb6 = { 9c c4 [2] ae e6 [2] a8 d3 [2] 86 d3 [2] b9 cf }

  condition:
    any of them
}