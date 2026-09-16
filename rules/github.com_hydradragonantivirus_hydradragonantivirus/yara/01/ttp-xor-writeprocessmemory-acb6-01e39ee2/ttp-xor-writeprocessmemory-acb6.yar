rule TTP_XOR_WriteProcessMemory_acb6 {
  strings:
    $key_acb6 = { fb c4 [2] c9 e6 [2] cf d3 [2] e1 d3 [2] de cf }

  condition:
    any of them
}