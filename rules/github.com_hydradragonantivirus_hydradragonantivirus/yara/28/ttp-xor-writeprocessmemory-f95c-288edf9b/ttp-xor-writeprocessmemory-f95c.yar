rule TTP_XOR_WriteProcessMemory_f95c {
  strings:
    $key_f95c = { ae 2e [2] 9c 0c [2] 9a 39 [2] b4 39 [2] 8b 25 }

  condition:
    any of them
}