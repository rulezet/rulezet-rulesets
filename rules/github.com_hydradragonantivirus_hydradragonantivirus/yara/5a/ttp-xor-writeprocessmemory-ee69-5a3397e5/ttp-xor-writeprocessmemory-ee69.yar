rule TTP_XOR_WriteProcessMemory_ee69 {
  strings:
    $key_ee69 = { b9 1b [2] 8b 39 [2] 8d 0c [2] a3 0c [2] 9c 10 }

  condition:
    any of them
}