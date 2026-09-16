rule TTP_XOR_WriteProcessMemory_615c {
  strings:
    $key_615c = { 36 2e [2] 04 0c [2] 02 39 [2] 2c 39 [2] 13 25 }

  condition:
    any of them
}