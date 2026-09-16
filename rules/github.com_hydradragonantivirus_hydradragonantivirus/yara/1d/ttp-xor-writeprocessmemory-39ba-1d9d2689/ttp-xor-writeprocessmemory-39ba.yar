rule TTP_XOR_WriteProcessMemory_39ba {
  strings:
    $key_39ba = { 6e c8 [2] 5c ea [2] 5a df [2] 74 df [2] 4b c3 }

  condition:
    any of them
}