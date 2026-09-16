rule TTP_XOR_WriteProcessMemory_388f {
  strings:
    $key_388f = { 6f fd [2] 5d df [2] 5b ea [2] 75 ea [2] 4a f6 }

  condition:
    any of them
}