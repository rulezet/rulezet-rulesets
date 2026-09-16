rule TTP_XOR_WriteProcessMemory_89ba {
  strings:
    $key_89ba = { de c8 [2] ec ea [2] ea df [2] c4 df [2] fb c3 }

  condition:
    any of them
}