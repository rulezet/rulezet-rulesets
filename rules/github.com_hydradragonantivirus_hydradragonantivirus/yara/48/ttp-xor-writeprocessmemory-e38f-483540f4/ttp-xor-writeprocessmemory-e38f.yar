rule TTP_XOR_WriteProcessMemory_e38f {
  strings:
    $key_e38f = { b4 fd [2] 86 df [2] 80 ea [2] ae ea [2] 91 f6 }

  condition:
    any of them
}