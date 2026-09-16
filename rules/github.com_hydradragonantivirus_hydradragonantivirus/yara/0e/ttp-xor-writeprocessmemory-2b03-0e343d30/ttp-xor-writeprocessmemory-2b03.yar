rule TTP_XOR_WriteProcessMemory_2b03 {
  strings:
    $key_2b03 = { 7c 71 [2] 4e 53 [2] 48 66 [2] 66 66 [2] 59 7a }

  condition:
    any of them
}