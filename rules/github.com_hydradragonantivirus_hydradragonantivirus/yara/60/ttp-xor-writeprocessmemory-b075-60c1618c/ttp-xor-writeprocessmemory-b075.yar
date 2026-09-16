rule TTP_XOR_WriteProcessMemory_b075 {
  strings:
    $key_b075 = { e7 07 [2] d5 25 [2] d3 10 [2] fd 10 [2] c2 0c }

  condition:
    any of them
}