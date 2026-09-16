rule TTP_XOR_WriteProcessMemory_fa0c {
  strings:
    $key_fa0c = { ad 7e [2] 9f 5c [2] 99 69 [2] b7 69 [2] 88 75 }

  condition:
    any of them
}