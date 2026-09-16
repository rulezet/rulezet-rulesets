rule TTP_XOR_WriteProcessMemory_a1fc {
  strings:
    $key_a1fc = { f6 8e [2] c4 ac [2] c2 99 [2] ec 99 [2] d3 85 }

  condition:
    any of them
}