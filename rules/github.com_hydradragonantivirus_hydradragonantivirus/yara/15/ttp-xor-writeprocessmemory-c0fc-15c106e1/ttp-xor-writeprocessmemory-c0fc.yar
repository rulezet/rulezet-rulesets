rule TTP_XOR_WriteProcessMemory_c0fc {
  strings:
    $key_c0fc = { 97 8e [2] a5 ac [2] a3 99 [2] 8d 99 [2] b2 85 }

  condition:
    any of them
}