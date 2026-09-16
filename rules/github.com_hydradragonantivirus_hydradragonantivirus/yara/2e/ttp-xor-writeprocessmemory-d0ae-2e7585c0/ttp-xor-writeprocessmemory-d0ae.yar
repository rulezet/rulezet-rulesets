rule TTP_XOR_WriteProcessMemory_d0ae {
  strings:
    $key_d0ae = { 87 dc [2] b5 fe [2] b3 cb [2] 9d cb [2] a2 d7 }

  condition:
    any of them
}