rule TTP_XOR_WriteProcessMemory_b63c {
  strings:
    $key_b63c = { e1 4e [2] d3 6c [2] d5 59 [2] fb 59 [2] c4 45 }

  condition:
    any of them
}