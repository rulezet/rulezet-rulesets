rule TTP_XOR_WriteProcessMemory_2b53 {
  strings:
    $key_2b53 = { 7c 21 [2] 4e 03 [2] 48 36 [2] 66 36 [2] 59 2a }

  condition:
    any of them
}