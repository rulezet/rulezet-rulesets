rule TTP_XOR_WriteProcessMemory_3b04 {
  strings:
    $key_3b04 = { 6c 76 [2] 5e 54 [2] 58 61 [2] 76 61 [2] 49 7d }

  condition:
    any of them
}