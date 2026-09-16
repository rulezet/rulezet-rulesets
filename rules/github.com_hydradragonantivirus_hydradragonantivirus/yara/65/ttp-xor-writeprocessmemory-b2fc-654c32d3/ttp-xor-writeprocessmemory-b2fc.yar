rule TTP_XOR_WriteProcessMemory_b2fc {
  strings:
    $key_b2fc = { e5 8e [2] d7 ac [2] d1 99 [2] ff 99 [2] c0 85 }

  condition:
    any of them
}