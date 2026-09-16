rule TTP_XOR_WriteProcessMemory_f9ba {
  strings:
    $key_f9ba = { ae c8 [2] 9c ea [2] 9a df [2] b4 df [2] 8b c3 }

  condition:
    any of them
}