rule TTP_XOR_WriteProcessMemory_fddf {
  strings:
    $key_fddf = { aa ad [2] 98 8f [2] 9e ba [2] b0 ba [2] 8f a6 }

  condition:
    any of them
}