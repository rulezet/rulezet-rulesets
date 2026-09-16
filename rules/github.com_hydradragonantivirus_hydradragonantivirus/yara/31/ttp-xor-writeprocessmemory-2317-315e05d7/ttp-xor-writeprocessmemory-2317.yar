rule TTP_XOR_WriteProcessMemory_2317 {
  strings:
    $key_2317 = { 74 65 [2] 46 47 [2] 40 72 [2] 6e 72 [2] 51 6e }

  condition:
    any of them
}