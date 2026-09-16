rule TTP_XOR_WriteProcessMemory_c88f {
  strings:
    $key_c88f = { 9f fd [2] ad df [2] ab ea [2] 85 ea [2] ba f6 }

  condition:
    any of them
}