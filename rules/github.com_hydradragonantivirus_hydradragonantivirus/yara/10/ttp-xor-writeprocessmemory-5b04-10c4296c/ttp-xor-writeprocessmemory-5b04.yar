rule TTP_XOR_WriteProcessMemory_5b04 {
  strings:
    $key_5b04 = { 0c 76 [2] 3e 54 [2] 38 61 [2] 16 61 [2] 29 7d }

  condition:
    any of them
}