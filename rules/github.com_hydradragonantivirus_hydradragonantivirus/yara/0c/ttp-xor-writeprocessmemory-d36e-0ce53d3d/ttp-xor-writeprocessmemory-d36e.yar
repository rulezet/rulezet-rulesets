rule TTP_XOR_WriteProcessMemory_d36e {
  strings:
    $key_d36e = { 84 1c [2] b6 3e [2] b0 0b [2] 9e 0b [2] a1 17 }

  condition:
    any of them
}