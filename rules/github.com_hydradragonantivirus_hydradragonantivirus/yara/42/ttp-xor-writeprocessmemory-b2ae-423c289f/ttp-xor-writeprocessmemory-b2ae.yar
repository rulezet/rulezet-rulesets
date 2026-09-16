rule TTP_XOR_WriteProcessMemory_b2ae {
  strings:
    $key_b2ae = { e5 dc [2] d7 fe [2] d1 cb [2] ff cb [2] c0 d7 }

  condition:
    any of them
}