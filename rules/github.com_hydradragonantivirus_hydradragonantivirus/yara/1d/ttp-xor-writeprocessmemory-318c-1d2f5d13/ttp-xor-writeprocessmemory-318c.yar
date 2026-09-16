rule TTP_XOR_WriteProcessMemory_318c {
  strings:
    $key_318c = { 66 fe [2] 54 dc [2] 52 e9 [2] 7c e9 [2] 43 f5 }

  condition:
    any of them
}