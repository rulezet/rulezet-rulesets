rule TTP_XOR_WriteProcessMemory_7cdf {
  strings:
    $key_7cdf = { 2b ad [2] 19 8f [2] 1f ba [2] 31 ba [2] 0e a6 }

  condition:
    any of them
}