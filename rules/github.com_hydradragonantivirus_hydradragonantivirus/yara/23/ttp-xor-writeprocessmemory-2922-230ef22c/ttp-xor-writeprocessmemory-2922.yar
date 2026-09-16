rule TTP_XOR_WriteProcessMemory_2922 {
  strings:
    $key_2922 = { 7e 50 [2] 4c 72 [2] 4a 47 [2] 64 47 [2] 5b 5b }

  condition:
    any of them
}