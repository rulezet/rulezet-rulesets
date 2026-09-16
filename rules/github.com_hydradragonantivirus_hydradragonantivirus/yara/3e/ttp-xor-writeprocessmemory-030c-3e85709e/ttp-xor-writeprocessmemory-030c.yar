rule TTP_XOR_WriteProcessMemory_030c {
  strings:
    $key_030c = { 54 7e [2] 66 5c [2] 60 69 [2] 4e 69 [2] 71 75 }

  condition:
    any of them
}