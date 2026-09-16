rule TTP_XOR_WriteProcessMemory_c9c8 {
  strings:
    $key_c9c8 = { 9e ba [2] ac 98 [2] aa ad [2] 84 ad [2] bb b1 }

  condition:
    any of them
}