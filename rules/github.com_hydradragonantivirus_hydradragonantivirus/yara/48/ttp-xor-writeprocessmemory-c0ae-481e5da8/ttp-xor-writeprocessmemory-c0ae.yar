rule TTP_XOR_WriteProcessMemory_c0ae {
  strings:
    $key_c0ae = { 97 dc [2] a5 fe [2] a3 cb [2] 8d cb [2] b2 d7 }

  condition:
    any of them
}