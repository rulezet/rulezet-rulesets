rule TTP_XOR_WriteProcessMemory_7dee {
  strings:
    $key_7dee = { 2a 9c [2] 18 be [2] 1e 8b [2] 30 8b [2] 0f 97 }

  condition:
    any of them
}