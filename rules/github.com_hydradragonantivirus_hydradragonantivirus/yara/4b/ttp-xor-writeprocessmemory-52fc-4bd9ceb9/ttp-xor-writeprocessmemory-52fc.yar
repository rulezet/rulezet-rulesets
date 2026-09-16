rule TTP_XOR_WriteProcessMemory_52fc {
  strings:
    $key_52fc = { 05 8e [2] 37 ac [2] 31 99 [2] 1f 99 [2] 20 85 }

  condition:
    any of them
}