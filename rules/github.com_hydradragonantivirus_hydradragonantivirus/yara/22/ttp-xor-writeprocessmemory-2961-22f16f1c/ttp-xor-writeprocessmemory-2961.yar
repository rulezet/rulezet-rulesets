rule TTP_XOR_WriteProcessMemory_2961 {
  strings:
    $key_2961 = { 7e 13 [2] 4c 31 [2] 4a 04 [2] 64 04 [2] 5b 18 }

  condition:
    any of them
}