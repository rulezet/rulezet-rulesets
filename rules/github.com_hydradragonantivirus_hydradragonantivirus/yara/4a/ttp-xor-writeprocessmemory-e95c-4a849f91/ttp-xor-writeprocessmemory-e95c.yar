rule TTP_XOR_WriteProcessMemory_e95c {
  strings:
    $key_e95c = { be 2e [2] 8c 0c [2] 8a 39 [2] a4 39 [2] 9b 25 }

  condition:
    any of them
}