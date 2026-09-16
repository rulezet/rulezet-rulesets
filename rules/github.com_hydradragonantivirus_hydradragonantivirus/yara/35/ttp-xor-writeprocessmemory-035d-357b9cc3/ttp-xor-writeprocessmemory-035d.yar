rule TTP_XOR_WriteProcessMemory_035d {
  strings:
    $key_035d = { 54 2f [2] 66 0d [2] 60 38 [2] 4e 38 [2] 71 24 }

  condition:
    any of them
}