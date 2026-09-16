rule TTP_XOR_WriteProcessMemory_f85c {
  strings:
    $key_f85c = { af 2e [2] 9d 0c [2] 9b 39 [2] b5 39 [2] 8a 25 }

  condition:
    any of them
}