rule TTP_XOR_WriteProcessMemory_090c {
  strings:
    $key_090c = { 5e 7e [2] 6c 5c [2] 6a 69 [2] 44 69 [2] 7b 75 }

  condition:
    any of them
}