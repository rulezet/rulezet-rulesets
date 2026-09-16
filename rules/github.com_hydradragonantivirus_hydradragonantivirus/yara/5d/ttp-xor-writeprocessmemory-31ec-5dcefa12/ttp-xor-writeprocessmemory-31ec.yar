rule TTP_XOR_WriteProcessMemory_31ec {
  strings:
    $key_31ec = { 66 9e [2] 54 bc [2] 52 89 [2] 7c 89 [2] 43 95 }

  condition:
    any of them
}