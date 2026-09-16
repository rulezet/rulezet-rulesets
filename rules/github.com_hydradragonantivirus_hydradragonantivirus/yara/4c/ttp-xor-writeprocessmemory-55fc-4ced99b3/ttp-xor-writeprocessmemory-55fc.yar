rule TTP_XOR_WriteProcessMemory_55fc {
  strings:
    $key_55fc = { 02 8e [2] 30 ac [2] 36 99 [2] 18 99 [2] 27 85 }

  condition:
    any of them
}