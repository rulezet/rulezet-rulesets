rule TTP_XOR_WriteProcessMemory_94fc {
  strings:
    $key_94fc = { c3 8e [2] f1 ac [2] f7 99 [2] d9 99 [2] e6 85 }

  condition:
    any of them
}