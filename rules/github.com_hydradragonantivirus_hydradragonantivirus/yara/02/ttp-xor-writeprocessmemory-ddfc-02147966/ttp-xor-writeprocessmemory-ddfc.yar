rule TTP_XOR_WriteProcessMemory_ddfc {
  strings:
    $key_ddfc = { 8a 8e [2] b8 ac [2] be 99 [2] 90 99 [2] af 85 }

  condition:
    any of them
}