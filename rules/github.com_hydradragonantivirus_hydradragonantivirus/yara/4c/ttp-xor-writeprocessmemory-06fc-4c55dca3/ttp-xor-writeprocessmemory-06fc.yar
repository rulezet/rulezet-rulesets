rule TTP_XOR_WriteProcessMemory_06fc {
  strings:
    $key_06fc = { 51 8e [2] 63 ac [2] 65 99 [2] 4b 99 [2] 74 85 }

  condition:
    any of them
}