rule TTP_XOR_WriteProcessMemory_d3ae {
  strings:
    $key_d3ae = { 84 dc [2] b6 fe [2] b0 cb [2] 9e cb [2] a1 d7 }

  condition:
    any of them
}