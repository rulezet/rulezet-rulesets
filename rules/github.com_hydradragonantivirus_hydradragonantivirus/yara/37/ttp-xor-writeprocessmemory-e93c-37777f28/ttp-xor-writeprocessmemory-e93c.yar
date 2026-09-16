rule TTP_XOR_WriteProcessMemory_e93c {
  strings:
    $key_e93c = { be 4e [2] 8c 6c [2] 8a 59 [2] a4 59 [2] 9b 45 }

  condition:
    any of them
}