rule TTP_XOR_WriteProcessMemory_5552 {
  strings:
    $key_5552 = { 02 20 [2] 30 02 [2] 36 37 [2] 18 37 [2] 27 2b }

  condition:
    any of them
}